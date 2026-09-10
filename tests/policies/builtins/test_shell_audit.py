"""
Tests for the ``allow_safe_shell`` audit trail
(:mod:`omnigent.policies.builtins.shell_audit`, wired into
:mod:`omnigent.policies.builtins.shell_readonly`).

Covers the three PDCA-relevant outcomes a reviewer needs to distinguish in
the JSONL log: a command that got auto-approved, one that was blocked (not
on the allowlist, never executed), and one that was blocked but later ran
anyway because a human manually approved it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from omnigent.policies.builtins.shell_audit import (
    AUDIT_LOG_PATH_ENV_VAR,
    build_shell_audit_event,
    record_shell_audit_event,
    shell_audit_log_path,
    truncate_for_audit,
)
from omnigent.policies.builtins.shell_readonly import allow_read_only_shell
from omnigent.policies.schema import PolicyEvent
from tests.policies.builtins.helpers import tool_call_event as tc
from tests.policies.builtins.helpers import tool_result_event as tr


@pytest.fixture(autouse=True)
def _audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the audit log to a per-test temp file."""
    path = tmp_path / "shell_commands.jsonl"
    monkeypatch.setenv(AUDIT_LOG_PATH_ENV_VAR, str(path))
    return path


def _read_records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _sh(command: str) -> PolicyEvent:
    return tc("sys_os_shell", {"command": command})


# ═══════════════════════════════════════════════════════════════════════
# shell_audit_log_path / build_shell_audit_event / record_shell_audit_event
# ═══════════════════════════════════════════════════════════════════════


def test_shell_audit_log_path_honors_env_override(tmp_path: Path, _audit_log: Path) -> None:
    assert shell_audit_log_path() == _audit_log


def test_record_shell_audit_event_appends_jsonl(_audit_log: Path) -> None:
    record_shell_audit_event(
        build_shell_audit_event(
            stage="decision",
            decision="auto_approved",
            tool="sys_os_shell",
            command="git status",
        )
    )
    record_shell_audit_event(
        build_shell_audit_event(
            stage="decision",
            decision="blocked",
            tool="sys_os_shell",
            command="rm -rf /",
        )
    )
    records = _read_records(_audit_log)
    assert len(records) == 2
    assert records[0]["decision"] == "auto_approved"
    assert records[1]["decision"] == "blocked"


def test_record_shell_audit_event_survives_unwritable_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A broken audit sink must never raise — see the module docstring."""
    # Point the log at a path whose parent can't be created (a file, not a dir).
    blocker = tmp_path / "not_a_directory"
    blocker.write_text("x")
    monkeypatch.setenv(AUDIT_LOG_PATH_ENV_VAR, str(blocker / "audit.jsonl"))
    record_shell_audit_event(
        build_shell_audit_event(
            stage="decision", decision="auto_approved", tool="sys_os_shell", command="ls"
        )
    )  # must not raise


def test_truncate_for_audit_clips_long_text() -> None:
    text = "a" * 3000
    truncated = truncate_for_audit(text, limit=10)
    assert truncated == ("a" * 10) + " [truncated]"
    assert truncate_for_audit("short") == "short"


# ═══════════════════════════════════════════════════════════════════════
# End-to-end through allow_read_only_shell: the 3 PDCA outcomes
# ═══════════════════════════════════════════════════════════════════════


def test_auto_approved_command_is_recorded_at_decision_time(_audit_log: Path) -> None:
    policy = allow_read_only_shell(presets=["core"])

    result = policy(_sh("cat README.md"))

    assert result is None or result["result"] == "ALLOW"
    records = _read_records(_audit_log)
    assert len(records) == 1
    record = records[0]
    assert record["stage"] == "decision"
    assert record["decision"] == "auto_approved"
    assert record["tool"] == "sys_os_shell"
    assert record["command"] == "cat README.md"


def test_blocked_command_is_recorded_and_never_gets_an_execution_row(_audit_log: Path) -> None:
    policy = allow_read_only_shell(presets=["core"])

    result = policy(_sh("rm -rf /"))

    assert result is not None
    assert result["result"] == "ASK"
    records = _read_records(_audit_log)
    assert len(records) == 1
    record = records[0]
    assert record["stage"] == "decision"
    assert record["decision"] == "blocked"
    assert record["command"] == "rm -rf /"
    assert record["reason"]
    # No corresponding execution row: the command never ran.
    assert all(r["stage"] != "execution" for r in records)


def test_manually_approved_command_is_recorded_at_execution_time(_audit_log: Path) -> None:
    """A command outside the allowlist that a human approved anyway.

    Simulates the full lifecycle: the ``tool_call`` gets blocked (ASK), then
    a ``tool_result`` arrives (as it would once a human approved the
    elicitation and the tool actually ran), correlated via ``request_data``.
    """
    policy = allow_read_only_shell(presets=["core"])

    call_result = policy(_sh("rm -rf /tmp/scratch"))
    assert call_result is not None
    assert call_result["result"] == "ASK"

    tool_output = json.dumps({"stdout": "", "stderr": "", "exit_code": 0})
    result_event = tr(
        "sys_os_shell",
        tool_output,
        request_arguments={"command": "rm -rf /tmp/scratch"},
    )
    outcome = policy(result_event)

    assert outcome is None  # auditing never gates tool_result
    records = _read_records(_audit_log)
    assert len(records) == 2
    decision_row, execution_row = records
    assert decision_row["stage"] == "decision"
    assert decision_row["decision"] == "blocked"
    assert execution_row["stage"] == "execution"
    assert execution_row["decision"] == "manually_approved"
    assert execution_row["command"] == "rm -rf /tmp/scratch"
    assert execution_row["exit_code"] == 0


def test_auto_approved_command_execution_is_also_recorded(_audit_log: Path) -> None:
    """An allowlisted command's tool_result is logged as auto_approved too."""
    policy = allow_read_only_shell(presets=["core"])

    policy(_sh("cat README.md"))
    tool_output = json.dumps({"stdout": "clean\n", "stderr": "", "exit_code": 0})
    result_event = tr(
        "sys_os_shell",
        tool_output,
        request_arguments={"command": "cat README.md"},
    )
    policy(result_event)

    records = _read_records(_audit_log)
    assert len(records) == 2
    assert records[0]["decision"] == "auto_approved"
    assert records[1]["stage"] == "execution"
    assert records[1]["decision"] == "auto_approved"
    assert records[1]["stdout_preview"] == "clean\n"


def test_tool_result_without_request_data_is_not_recorded(_audit_log: Path) -> None:
    """No correlation available (e.g. the runner-side gate) — skip, don't guess."""
    policy = allow_read_only_shell(presets=["core"])

    outcome = policy(tr("sys_os_shell", json.dumps({"stdout": "", "exit_code": 0})))

    assert outcome is None
    assert _read_records(_audit_log) == []


def test_non_shell_tool_result_is_ignored(_audit_log: Path) -> None:
    policy = allow_read_only_shell(presets=["core"])

    outcome = policy(tr("mcp__google__gmail_send", "{}", request_arguments={"to": "a@b.com"}))

    assert outcome is None
    assert _read_records(_audit_log) == []


def test_audit_failure_does_not_change_the_policy_verdict(
    monkeypatch: pytest.MonkeyPatch, _audit_log: Path
) -> None:
    """A raising audit hook must not turn into a DENY-by-exception.

    ``allow_read_only_shell`` never returns DENY itself, so this asserts the
    verdict stays ALLOW/ASK even when the audit sink is broken (see
    ``record_shell_audit_event``'s docstring — policy callables that raise
    are treated as fail-closed DENY by the engine).
    """
    import omnigent.policies.builtins.shell_readonly as shell_readonly_mod

    def _boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit sink exploded")

    monkeypatch.setattr(shell_readonly_mod, "record_shell_audit_event", _boom)
    policy = allow_read_only_shell(presets=["core"])

    allowed = policy(_sh("cat README.md"))
    blocked = policy(_sh("rm -rf /"))

    assert allowed is None or allowed["result"] == "ALLOW"
    assert blocked is not None
    assert blocked["result"] == "ASK"
