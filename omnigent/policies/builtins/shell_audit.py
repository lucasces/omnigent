"""Local JSONL audit trail for ``allow_safe_shell`` decisions (PDCA support).

:mod:`shell_readonly` (the ``allow_safe_shell`` policy) decides, per shell
command, whether it auto-runs or needs a human. That decision -- and, when the
command goes on to actually run, its outcome -- is appended here as one JSON
line per event to ``<data-dir>/audit/shell_commands.jsonl`` (see
:func:`omnigent.process_logging.data_dir`, the same runtime directory every
other Omnigent entrypoint writes local state under; override with
``OMNIGENT_SHELL_AUDIT_LOG`` for tests or a custom location).

The log exists to close a PDCA loop on the allowlist after the fact --
tail it, load it into a notebook, ``jq`` it -- to see which commands were
auto-approved, which needed a human, and which never ran at all. It is not
itself an enforcement mechanism: writing it never blocks, transforms, or
denies a command.

Two ``stage``s land per command:

- ``"decision"`` -- written when the policy evaluates a ``tool_call``, before
  the command runs. ``decision`` is ``"auto_approved"`` (matched the
  allowlist) or ``"blocked"`` (did not match -- the command is on hold until
  a human approves it, via whatever ASK/elicitation flow the harness wires
  up).
- ``"execution"`` -- written when a ``tool_result`` arrives for a shell tool,
  i.e. the command actually ran (only possible after an ALLOW, whether
  auto-approved or a human approved the pending ASK). ``decision`` mirrors
  what the original command would have gotten: ``"auto_approved"`` or
  ``"manually_approved"``.

Reading the two stages together tells the PDCA story: a ``"decision"`` row
with ``decision="blocked"`` and no matching ``"execution"`` row means the
command was rejected, timed out, or is still pending -- exactly the signal
needed to review which auto-approval rules fire often (many ``"decision"``
rows with ``decision="auto_approved"`` for the same command shape) and which
blocked commands turn out to be routinely approved anyway (candidates for a
new allowlist pattern).

Writing is best-effort: a failure to append (disk full, permissions, a
concurrent rotation) is logged and swallowed rather than raised -- a broken
audit sink must never block or fail a shell command.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypedDict

_logger = logging.getLogger(__name__)

# Overrides the default ``<data-dir>/audit/shell_commands.jsonl`` path --
# tests point this at a temp file; a deployment could redirect it too.
AUDIT_LOG_PATH_ENV_VAR = "OMNIGENT_SHELL_AUDIT_LOG"

# Serializes append calls across threads in one process. FunctionPolicy
# callables run via ``asyncio.to_thread`` (see omnigent.policies.function),
# so concurrent shell tool calls can race to append at once; a single
# process-wide lock keeps each JSON line intact (no interleaved writes)
# without needing a file lock for the (rare) multi-process case.
_write_lock = threading.Lock()

# Preview cap for command/stdout/stderr text landing in one audit line --
# long enough to review, short enough that one huge command output can't
# blow up the log file.
_PREVIEW_LIMIT = 2000

Stage = Literal["decision", "execution"]
Decision = Literal["auto_approved", "blocked", "manually_approved"]


class ShellAuditEvent(TypedDict, total=False):
    """One JSONL row in the shell-command audit log.

    :param timestamp: UTC ISO-8601 timestamp of the event.
    :param stage: ``"decision"`` (pre-execution verdict) or ``"execution"``
        (the command actually ran).
    :param decision: ``"auto_approved"``, ``"blocked"``, or
        ``"manually_approved"`` -- see the module docstring for how the two
        stages combine to tell the full story of one command.
    :param tool: The shell tool name, e.g. ``"sys_os_shell"``.
    :param command: The full command string that was evaluated / executed.
    :param reason: The policy's reason text, when the verdict wasn't a
        plain match (e.g. which segment isn't allowlisted).
    :param session_id: Best-effort session identifier -- populated for
        runner-hosted sessions; may be ``None`` (see
        :func:`omnigent.policies.builtins.shell_readonly._actor_identity`
        for the fallback chain and its limits).
    :param user_id: Best-effort identity of the user driving the session.
    :param exit_code: The command's exit code, when known (``"execution"``
        rows only).
    :param stdout_preview: Truncated stdout, when known.
    :param stderr_preview: Truncated stderr, when known.
    """

    timestamp: str
    stage: Stage
    decision: Decision
    tool: str
    command: str | None
    reason: str | None
    session_id: str | None
    user_id: str | None
    exit_code: int | None
    stdout_preview: str | None
    stderr_preview: str | None


def shell_audit_log_path() -> Path:
    """Resolve the JSONL audit-log path.

    :returns: ``$OMNIGENT_SHELL_AUDIT_LOG`` when set, else
        ``<data-dir>/audit/shell_commands.jsonl``.
    """
    override = os.environ.get(AUDIT_LOG_PATH_ENV_VAR)
    if override:
        return Path(override).expanduser()
    from omnigent.process_logging import data_dir

    return data_dir() / "audit" / "shell_commands.jsonl"


def truncate_for_audit(text: str, *, limit: int = _PREVIEW_LIMIT) -> str:
    """Truncate *text* for an audit-log field.

    :param text: Raw text (a command, stdout, or stderr).
    :param limit: Maximum characters kept.
    :returns: *text* unchanged when short enough, else clipped with a
        ``" [truncated]"`` marker.
    """
    return text if len(text) <= limit else text[:limit] + " [truncated]"


def build_shell_audit_event(
    *,
    stage: Stage,
    decision: Decision,
    tool: str,
    command: str | None,
    reason: str | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    exit_code: int | None = None,
    stdout_preview: str | None = None,
    stderr_preview: str | None = None,
) -> ShellAuditEvent:
    """Build one :class:`ShellAuditEvent`, stamped with the current time.

    :returns: A fully-populated audit event ready for
        :func:`record_shell_audit_event`.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "decision": decision,
        "tool": tool,
        "command": command,
        "reason": reason,
        "session_id": session_id,
        "user_id": user_id,
        "exit_code": exit_code,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
    }


def record_shell_audit_event(event: ShellAuditEvent) -> None:
    """Append one audit event as a JSON line.

    Best-effort: creates the parent directory on first use, and swallows
    (logging a warning for) any I/O failure rather than raising -- a policy
    callable that raises is treated as a fail-closed DENY by the engine
    (see ``omnigent.policies.function``), and an audit-log hiccup must never
    turn into a denied shell command.

    :param event: The event to append, from :func:`build_shell_audit_event`.
    """
    path = shell_audit_log_path()
    line = json.dumps(event, sort_keys=True)
    try:
        with _write_lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except OSError:
        _logger.warning("failed to write shell command audit record", exc_info=True)


__all__ = [
    "AUDIT_LOG_PATH_ENV_VAR",
    "Decision",
    "ShellAuditEvent",
    "Stage",
    "build_shell_audit_event",
    "record_shell_audit_event",
    "shell_audit_log_path",
    "truncate_for_audit",
]
