"""Bridge utilities for native Kiro TUI sessions."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict

from omnigent._platform import stable_user_id
from omnigent.util.json_types import JsonObject as _JsonObject


class _McpServerEntry(TypedDict):
    command: str
    args: list[str]
    env: dict[str, str]


class _KiroMcpConfig(TypedDict):
    mcpServers: dict[str, _McpServerEntry]


KIRO_NATIVE_BRIDGE_DIR_ENV_VAR = "HARNESS_KIRO_NATIVE_BRIDGE_DIR"
KIRO_ACP_RECORD_PATH_ENV_VAR = "KIRO_ACP_RECORD_PATH"

_BRIDGE_ROOT = Path(tempfile.gettempdir()) / f"omnigent-{stable_user_id()}" / "kiro-native"
_TMUX_FILE = "tmux.json"
_FORWARDER_READY_FILE = "kiro_session_forwarder_ready.json"
_ACP_RECORD_FILE = "kiro_acp_record.jsonl"
# Shared Omnigent MCP relay (serve-mcp) registration for kiro.
_MCP_SERVER_NAME = "omnigent"
_MCP_BRIDGE_CONFIG_FILE = "bridge.json"
# kiro reads workspace-scoped MCP servers from ``<workspace>/.kiro/settings/mcp.json``
# (confirmed against kiro-cli 2.10.0). Mirrors cursor-native's ``.cursor/mcp.json``.
_WORKSPACE_MCP_CONFIG_REL = Path(".kiro") / "settings" / "mcp.json"
_TMUX_READY_TIMEOUT_S = 30.0
# kiro's TUI shows "Initializing · type to queue a message" while it boots its
# JS renderer; on a slow or degraded network that boot measured 35-38s, past the
# 30s gate, so the first web turn failed on an otherwise healthy TUI. While that
# banner is on the pane kiro is provably still coming up, so keep waiting up to
# this longer ceiling instead of giving up at ``_TMUX_READY_TIMEOUT_S``.
_KIRO_BOOT_READY_TIMEOUT_S = 120.0
_KIRO_BOOT_MARKERS = ("Initializing",)
_TMUX_SEND_TIMEOUT_S = 10.0
_POLL_INTERVAL_S = 0.2
_TYPE_SETTLE_S = 0.3
_TYPE_COMMIT_TIMEOUT_S = 5.0
_SUBMIT_VERIFY_TIMEOUT_S = 5.0
_SUBMIT_RETRY_INTERVAL_S = 0.5
_PERMISSION_KEY_INTERVAL_S = 0.3
_PERMISSION_ENTER_SETTLE_S = 0.5
# How long to keep re-capturing the pane for a focus check to settle before
# giving up on a permission verdict (see ``_wait_for_focus``). Short relative
# to ``_TMUX_READY_TIMEOUT_S`` because this only needs to absorb a tmux
# redraw race, not wait out a genuinely wedged TUI.
_PERMISSION_FOCUS_RETRY_TIMEOUT_S = 5.0
_KIRO_SEPARATOR = "────"
_KIRO_INPUT_READY_MARKERS = (
    "ask a question or describe a task",
    "Type to steer",
)
_PASTE_BUFFER = "omnigent-kiro-paste"
# "Trust, always allow in this session" is deliberately excluded: Kiro omits
# it for some prompt kinds (KiroPermissionRequest.always_option_id can be
# None, a 2-row menu), and requiring it here meant _kiro_permission_prompt_active
# could never recognize such a prompt as active at all — every accept/decline
# delivery attempt against a 2-row prompt timed out in
# _wait_for_kiro_permission_prompt before ever sending a keystroke.
_KIRO_PERMISSION_MARKERS = (
    "requires approval",
    "Yes, single permission",
    "No (Tab to edit)",
)

# Ambient provider/cloud/CI credentials that must not be inherited by Kiro.
KIRO_NATIVE_ENV_UNSET = [
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "CI",
    "DATABRICKS_CLIENT_SECRET",
    "DATABRICKS_CONFIG_PROFILE",
    "DATABRICKS_HOST",
    "DATABRICKS_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
]

_CHILD_ENV_ALLOWLIST = [
    "COLORTERM",
    "DISPLAY",
    "HOME",
    "KIRO_CONFIG_HOME",
    "KIRO_HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
]


def bridge_root() -> Path:
    """Return the uid-scoped Kiro-native bridge root.

    Mirrors the sibling harnesses' ``bridge_root`` accessor so the shared
    ``serve-mcp`` / relay infrastructure in ``claude_native_bridge`` can
    recognize Kiro bridge dirs as a trusted root.
    """
    return _BRIDGE_ROOT


def bridge_dir_for_session_id(session_id: str) -> Path:
    """Return the per-session Kiro bridge directory."""
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
    return _BRIDGE_ROOT / digest


def prepare_bridge_dir(session_id: str) -> Path:
    """Create and return the per-session Kiro bridge directory."""
    bridge_dir = bridge_dir_for_session_id(session_id)
    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(bridge_dir, 0o700)
    return bridge_dir


def acp_record_path(bridge_dir: Path) -> Path:
    """Return the per-session Kiro TUI ACP recorder file path."""
    return bridge_dir / _ACP_RECORD_FILE


def write_mcp_bridge_config(bridge_dir: Path) -> None:
    """Write the token config the shared Omnigent MCP bridge requires at boot.

    ``serve-mcp`` (``omnigent.harnesses.claude_native.bridge``) reads ``bridge.json`` and
    refuses to start without a ``token``. Mirrors cursor-native's writer;
    idempotent so a resume reuses the existing token.
    """
    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = bridge_dir / _MCP_BRIDGE_CONFIG_FILE
    if config_path.exists():
        return
    payload = {"token": secrets.token_urlsafe(32)}
    tmp = bridge_dir / (_MCP_BRIDGE_CONFIG_FILE + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, config_path)


def build_kiro_mcp_config(
    bridge_dir: Path, *, python_executable: str | None = None
) -> _KiroMcpConfig:
    """Build the kiro ``mcpServers`` entry for the Omnigent relay MCP server.

    Reuses the shared stdio ``serve-mcp`` server (the same one cursor/claude use)
    pointed at this session's bridge dir. kiro's mcp.json schema is
    ``{"mcpServers": {name: {command, args, env}}}`` (kiro-cli 2.10.0); it has no
    per-server auto-approve field, so Omnigent MCP tool calls surface through
    kiro's approval prompt (mirrored to the web as elicitation cards) rather than
    being auto-trusted here.
    """
    python = python_executable or sys.executable
    return {
        "mcpServers": {
            _MCP_SERVER_NAME: {
                "command": python,
                "args": [
                    "-I",
                    "-m",
                    "omnigent.harnesses.claude_native.bridge",
                    "serve-mcp",
                    "--bridge-dir",
                    str(bridge_dir),
                ],
                "env": {"TMPDIR": os.environ.get("TMPDIR", "/tmp")},
            }
        }
    }


def write_kiro_workspace_mcp_config(
    workspace: Path,
    bridge_dir: Path,
    *,
    python_executable: str | None = None,
) -> Path:
    """Write the workspace-scoped kiro MCP config declaring the Omnigent server.

    kiro-cli has no launch-time mcp-config flag, so the server is declared in the
    workspace's ``.kiro/settings/mcp.json`` (mirrors cursor-native's
    ``.cursor/mcp.json``). The Omnigent entry is *merged* into any existing
    workspace config so a user's own workspace MCP servers are preserved. Also
    writes the bridge ``token`` ``serve-mcp`` needs. Returns the config path.
    """
    write_mcp_bridge_config(bridge_dir)
    path = workspace / _WORKSPACE_MCP_CONFIG_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    config: _JsonObject = {}
    if path.exists():
        with contextlib.suppress(OSError, ValueError):
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config = loaded
    servers = config.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    servers[_MCP_SERVER_NAME] = build_kiro_mcp_config(
        bridge_dir, python_executable=python_executable
    )["mcpServers"][_MCP_SERVER_NAME]
    config["mcpServers"] = servers
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def build_kiro_native_spawn_env(session_id: str) -> dict[str, str]:
    """Build the ``HARNESS_KIRO_NATIVE_*`` env for the harness executor."""
    bridge_dir = prepare_bridge_dir(session_id)
    return {KIRO_NATIVE_BRIDGE_DIR_ENV_VAR: str(bridge_dir)}


def build_kiro_native_terminal_env(
    session_id: str,
    *,
    source_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the allowlisted child environment for ``kiro-cli``."""
    env = os.environ if source_env is None else source_env
    child = {key: env[key] for key in _CHILD_ENV_ALLOWLIST if env.get(key)}
    bridge_dir = prepare_bridge_dir(session_id)
    child[KIRO_NATIVE_BRIDGE_DIR_ENV_VAR] = str(bridge_dir)
    child[KIRO_ACP_RECORD_PATH_ENV_VAR] = str(acp_record_path(bridge_dir))
    return child


def write_tmux_target(
    bridge_dir: Path,
    *,
    socket_path: Path,
    tmux_target: str,
    pid: int | None = None,
    requires_forwarder_ready: bool = False,
) -> None:
    """Advertise the tmux socket + target for the running Kiro terminal."""
    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload: _JsonObject = {
        "socket_path": str(socket_path),
        "tmux_target": tmux_target,
        "updated_at": time.time(),
    }
    if requires_forwarder_ready:
        payload["requires_forwarder_ready"] = True
    if pid is not None:
        payload["pid"] = pid
    tmp = bridge_dir / (_TMUX_FILE + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, bridge_dir / _TMUX_FILE)


def read_tmux_info(bridge_dir: Path) -> dict[str, str] | None:
    """Return ``{socket_path, tmux_target}`` from ``tmux.json``, or ``None``."""
    try:
        raw = (bridge_dir / _TMUX_FILE).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    socket_path = data.get("socket_path")
    tmux_target = data.get("tmux_target")
    if (
        isinstance(socket_path, str)
        and socket_path
        and isinstance(tmux_target, str)
        and tmux_target
    ):
        return {"socket_path": socket_path, "tmux_target": tmux_target}
    return None


def write_forwarder_ready(bridge_dir: Path) -> None:
    """Mark the Kiro JSONL forwarder as attached and caught up."""
    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = {"updated_at": time.time()}
    tmp = bridge_dir / (_FORWARDER_READY_FILE + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, bridge_dir / _FORWARDER_READY_FILE)


def _read_bridge_json(bridge_dir: Path, filename: str) -> _JsonObject | None:
    try:
        raw = (bridge_dir / filename).read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _wait_for_forwarder_ready_if_required(
    bridge_dir: Path,
    *,
    tmux_info: _JsonObject,
    timeout_s: float,
) -> None:
    if tmux_info.get("requires_forwarder_ready") is not True:
        return
    tmux_updated_at = tmux_info.get("updated_at")
    if not isinstance(tmux_updated_at, int | float):
        tmux_updated_at = 0.0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ready = _read_bridge_json(bridge_dir, _FORWARDER_READY_FILE)
        ready_updated_at = ready.get("updated_at") if ready is not None else None
        if isinstance(ready_updated_at, int | float) and ready_updated_at >= tmux_updated_at:
            return
        time.sleep(_POLL_INTERVAL_S)
    raise RuntimeError("kiro-native session forwarder was not ready before injection")


def _wait_for_tmux_info(bridge_dir: Path, *, timeout_s: float) -> dict[str, str]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = read_tmux_info(bridge_dir)
        if info is not None:
            return info
        time.sleep(_POLL_INTERVAL_S)
    raise RuntimeError(f"kiro-native tmux target was not advertised within {timeout_s:.0f}s")


def _run_tmux(socket_path: str, *args: str) -> None:
    try:
        proc = subprocess.run(
            ["tmux", "-S", socket_path, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=_TMUX_SEND_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tmux command timed out after {_TMUX_SEND_TIMEOUT_S}s") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "<no output>"
        raise RuntimeError(f"tmux command failed (rc={proc.returncode}): {detail}")


def _session_alive(socket_path: str, tmux_target: str) -> bool:
    try:
        proc = subprocess.run(
            ["tmux", "-S", socket_path, "has-session", "-t", tmux_target],
            check=False,
            capture_output=True,
            text=True,
            timeout=_TMUX_SEND_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0


def _capture_pane(socket_path: str, tmux_target: str) -> str:
    """Capture pane contents including scrollback; return "" on failure.

    ``-J`` joins lines tmux soft-wrapped at the pane width, and ``-S -300``
    extends the capture into scrollback rather than just the visible
    viewport. Both are strictly additive on top of the plain visible-pane
    capture — they only add lines above/before what was already there — so
    they can't change behavior for callers that search from the bottom of
    the pane (all of them, since Kiro's UI chrome markers they look for sit
    near the bottom of the transcript).
    """
    try:
        proc = subprocess.run(
            [
                "tmux",
                "-S",
                socket_path,
                "capture-pane",
                "-p",
                "-J",
                "-S",
                "-300",
                "-t",
                tmux_target,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_TMUX_SEND_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _submit_needle(content: str) -> str:
    """Return a small marker used to identify the pasted draft."""
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    for line in normalized.split("\n"):
        for idx, ch in enumerate(line):
            if ord(ch) < 0x20:
                line = line[:idx]
                break
        line = line.strip()
        if line:
            return line[:24]
    return ""


def _kiro_input_region(pane: str) -> str:
    """Return Kiro's bottom input region, excluding transcript history."""
    lines = pane.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        if _KIRO_SEPARATOR in lines[index]:
            return "\n".join(lines[index + 1 :])
    return "\n".join(lines[-8:])


def _draft_in_input_region(pane: str, needle: str, baseline_region: str) -> bool:
    """Return whether the draft is still visible in Kiro's input region."""
    region = _kiro_input_region(pane)
    if not needle or region == baseline_region:
        return False
    normalized_needle = needle.strip()
    if not normalized_needle:
        return False
    return any(
        line == normalized_needle or line.startswith(normalized_needle)
        for line in _kiro_draft_candidate_lines(region)
    )


def _kiro_draft_candidate_lines(region: str) -> list[str]:
    """Return input-region lines that can represent editable draft text."""
    candidates: list[str] = []
    for raw_line in region.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("kiro_default"):
            continue
        if line.startswith("/copy"):
            continue
        if line.startswith("▸ Credits:"):
            continue
        if any(marker in line for marker in _KIRO_INPUT_READY_MARKERS):
            continue
        candidates.append(line)
    return candidates


def _kiro_input_ready(pane: str) -> bool:
    """Return whether Kiro's bottom input prompt is ready to receive text."""
    region = _kiro_input_region(pane)
    return any(marker in region for marker in _KIRO_INPUT_READY_MARKERS)


def _kiro_permission_prompt_active(pane: str) -> bool:
    """Return whether Kiro's visible approval prompt is active."""
    return all(marker in pane for marker in _KIRO_PERMISSION_MARKERS)


# Each focus check matches only a SHORT, unique prefix of the focused ("❯ ")
# option row — never the full label. A narrow pane hard-wraps a long row like
# "❯ Trust, always allow in this session" onto a second line ("❯ Trust, always
# allow in this" / "  session"), and ``_capture_pane``'s ``-J`` only rejoins
# tmux's own soft-wraps, not the break Kiro itself emits. Matching the full
# string then silently fails, ``_wait_for_focus`` times out, and the verdict
# keystroke is never confirmed (RuntimeError "... not safely focused"), wedging
# the prompt — with "single"/"No" delivering fine (short rows never wrap) while
# "Trust, always allow" never does. The prefixes below stay unique among Kiro's
# three options yet short enough to survive any pane width, mirroring the
# "keep markers short" discipline the idle markers already follow (see
# inner/terminal.py ``_IDLE_MARKER_SUBSTRINGS``).
def _kiro_permission_focus_on_one_time_allow(pane: str) -> bool:
    """Return whether Kiro's approval picker is focused on one-time allow."""
    return any(line.strip().startswith("❯ Yes,") for line in pane.splitlines())


def _kiro_permission_focus_on_always_allow(pane: str) -> bool:
    """Return whether Kiro's approval picker is focused on trust-always."""
    return any(line.strip().startswith("❯ Trust,") for line in pane.splitlines())


def _kiro_permission_focus_on_reject(pane: str) -> bool:
    """Return whether Kiro's approval picker is focused on one-time reject."""
    return any(line.strip().startswith("❯ No") for line in pane.splitlines())


# Kiro V3 batches every pending subagent tool-call approval behind one
# top-level picker ("N tool approvals pending from subagents", options
# (a)/(f)/(c)/(x)) instead of showing each one modally like a non-subagent
# prompt (see _kiro_permission_prompt_active, which never matches this
# picker — none of its markers appear on it). "(c) Configure individually"
# opens AGENT MONITOR, a per-subagent view where each pending prompt is
# answered with its own "y approve · n deny · t trust" shortcuts instead of
# the top-level Down/Enter picker navigation.
#
# The marker must be count-agnostic: Kiro pluralizes the header by the
# pending count, so a batch of exactly ONE renders "1 tool approval pending
# from subagents" (singular) while 2+ render "N tool approvals pending from
# subagents" (plural). Matching the plural "approvals" missed the singular
# case entirely, so a lone pending subagent approval was never detected and
# _focus_kiro_subagent_prompt raised "subagent approval prompt was not
# visible", wedging the session on every single-pending batch. The suffix
# below is present verbatim in both forms and unique to this picker.
_KIRO_SUBAGENT_BATCH_MARKER = "pending from subagents"
_KIRO_AGENT_MONITOR_MARKER = "AGENT MONITOR"
_KIRO_SUBAGENT_OUTPUT_HEADER_PREFIX = "SUBAGENT OUTPUT ["
# Matches an AGENT MONITOR subagent row, e.g. "  1 ⚠ sleep1 Shell" or
# "  2 ✓ sleep2 Completed" — group 1 is the 1-based jump digit, group 2 is
# the subagent's name (the token right after the status glyph).
_KIRO_AGENT_MONITOR_ROW_RE = re.compile(r"^\s*(\d+)\s+\S+\s+(\S+)")


def _kiro_subagent_batch_prompt_active(pane: str) -> bool:
    """Return whether Kiro's batched subagent-approval picker is showing."""
    return _KIRO_SUBAGENT_BATCH_MARKER in pane


def _kiro_agent_monitor_active(pane: str) -> bool:
    """Return whether Kiro's per-subagent AGENT MONITOR view is open."""
    return _KIRO_AGENT_MONITOR_MARKER in pane


def _kiro_agent_monitor_subagent_focused(pane: str, subagent_name: str) -> bool:
    """Return whether AGENT MONITOR is showing *subagent_name*'s own pending prompt."""
    header = f"{_KIRO_SUBAGENT_OUTPUT_HEADER_PREFIX}{subagent_name}]"
    if header not in pane:
        return False
    return "requires approval" in pane and "y approve" in pane


def _kiro_agent_monitor_subagent_index(pane: str, subagent_name: str) -> int | None:
    """Return the 1-based row number AGENT MONITOR lists *subagent_name* under."""
    for line in pane.splitlines():
        match = _KIRO_AGENT_MONITOR_ROW_RE.match(line)
        if match and match.group(2) == subagent_name:
            return int(match.group(1))
    return None


def _focus_kiro_subagent_prompt(
    socket_path: str,
    tmux_target: str,
    *,
    subagent_name: str,
    timeout_s: float,
) -> str:
    """Navigate into AGENT MONITOR and focus *subagent_name*'s own pending prompt.

    Drills through the batched picker's "(c) Configure individually" option
    (single-key shortcut, no Down-navigation needed) into AGENT MONITOR, then
    jumps to *subagent_name*'s row via its 1-based jump digit — the only way
    to answer one specific subagent's request without also resolving every
    other pending one via the top-level "(a) Approve all pending" (which was
    the previous behavior and would have delivered a verdict no human
    actually gave to whichever other request happened to be pending too).

    :raises RuntimeError: if neither the batch picker nor AGENT MONITOR ever
        appears, if AGENT MONITOR never opens after "c", if *subagent_name*
        has no row in AGENT MONITOR (Kiro hasn't listed it yet), or if its
        row never becomes focused after jumping to it.
    """
    pane = _wait_for_focus(
        socket_path,
        tmux_target,
        focus_check=lambda _p: True,
        timeout_s=timeout_s,
        prompt_active_check=lambda p: (
            _kiro_agent_monitor_active(p) or _kiro_subagent_batch_prompt_active(p)
        ),
    )
    if not (_kiro_agent_monitor_active(pane) or _kiro_subagent_batch_prompt_active(pane)):
        raise RuntimeError(
            "kiro-native subagent approval prompt was not visible before verdict delivery"
        )
    if not _kiro_agent_monitor_active(pane):
        _run_tmux(socket_path, "send-keys", "-t", tmux_target, "c")
        time.sleep(_PERMISSION_KEY_INTERVAL_S)
        pane = _wait_for_focus(
            socket_path,
            tmux_target,
            focus_check=lambda _p: True,
            timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
            prompt_active_check=_kiro_agent_monitor_active,
        )
        if not _kiro_agent_monitor_active(pane):
            raise RuntimeError("kiro-native agent monitor did not open before verdict delivery")
    if _kiro_agent_monitor_subagent_focused(pane, subagent_name):
        return pane
    index = _kiro_agent_monitor_subagent_index(pane, subagent_name)
    if index is None:
        raise RuntimeError(f"kiro-native agent monitor has no row for subagent {subagent_name!r}")
    if index > 9:
        # Observed jump shortcuts are single digits ("1-2 jump" for a 2-agent
        # batch); a 10th+ subagent has no known single-keystroke jump and
        # sending "10" would send two separate keystrokes ('1' then '0'),
        # each jumping to a different (wrong) row instead of one action.
        raise RuntimeError(
            "kiro-native agent monitor jump shortcuts beyond 9 subagents are unsupported "
            f"(subagent {subagent_name!r} is row {index})"
        )
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, str(index))
    time.sleep(_PERMISSION_KEY_INTERVAL_S)
    pane = _wait_for_focus(
        socket_path,
        tmux_target,
        focus_check=lambda p: _kiro_agent_monitor_subagent_focused(p, subagent_name),
        timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
        prompt_active_check=_kiro_agent_monitor_active,
    )
    if not _kiro_agent_monitor_subagent_focused(pane, subagent_name):
        raise RuntimeError(
            f"kiro-native subagent {subagent_name!r} prompt was not focused before delivery"
        )
    return pane


# Selecting "Trust, always allow in this session" doesn't complete the
# verdict by itself on prompt kinds that support scoped trust (observed:
# shell) — Kiro opens a second, local-only submenu asking exactly what to
# trust (e.g. "Full command" / "Partial command" / "Base command" / "Entire
# tool" for a shell prompt). Both markers sit together on the submenu's own
# header line ("shell requires approval · trust options"), distinguishing it
# from the top-level prompt's plain "shell requires approval" header.
_KIRO_TRUST_SCOPE_HEADER_MARKERS = ("requires approval", "trust options")


def _kiro_trust_scope_active(pane: str) -> bool:
    """Return whether Kiro's trust-scope submenu (post "Trust, always allow") is active."""
    return any(
        all(marker in line for marker in _KIRO_TRUST_SCOPE_HEADER_MARKERS)
        for line in pane.splitlines()
    )


def _kiro_trust_scope_header_index(pane_lines: list[str]) -> int | None:
    """Return the index of the trust-scope submenu's header line, if present."""
    return next(
        (
            i
            for i, line in enumerate(pane_lines)
            if all(marker in line for marker in _KIRO_TRUST_SCOPE_HEADER_MARKERS)
        ),
        None,
    )


def _kiro_trust_scope_rows(pane: str) -> list[str]:
    """Return the trust-scope submenu's option rows, cursor glyph stripped, in on-screen order.

    Captured verbatim from the live pane rather than reconstructed, so a
    caller mirrors exactly what Kiro itself is showing right now — including
    per-prompt dynamic text (e.g. "Partial command   sleep 5 *") — without
    this bridge needing to understand how Kiro derives partial/base command
    patterns.
    """
    lines = pane.splitlines()
    header_idx = _kiro_trust_scope_header_index(lines)
    if header_idx is None:
        return []
    rows: list[str] = []
    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped:
            if rows:
                break
            continue
        if _KIRO_SEPARATOR in stripped or stripped.startswith("esc "):
            break
        rows.append(stripped.removeprefix("❯").strip())
    return rows


def _kiro_trust_scope_focused_index(pane: str) -> int | None:
    """Return the 0-based index of the trust-scope row currently focused, if any."""
    lines = pane.splitlines()
    header_idx = _kiro_trust_scope_header_index(lines)
    if header_idx is None:
        return None
    index = 0
    for line in lines[header_idx + 1 :]:
        stripped = line.strip()
        if not stripped:
            continue
        if _KIRO_SEPARATOR in stripped or stripped.startswith("esc "):
            break
        if stripped.startswith("❯"):
            return index
        index += 1
    return None


def _wait_for_kiro_permission_prompt(
    socket_path: str,
    tmux_target: str,
    *,
    timeout_s: float,
) -> None:
    """Wait until Kiro has rendered an approval prompt before typing a verdict.

    Deliberately does not try to verify the visible prompt's *content*
    matches the ACP request we're answering. Kiro's TUI is strictly modal —
    it blocks on ``session/request_permission`` and cannot render the next
    prompt until the current one gets an answer — so there is only ever one
    live prompt to match against, making content verification redundant.
    Reconstructing that content from the rendered pane (undoing Kiro's own
    line wrapping, which breaks mid-word with no space and produces blank
    lines inside multi-line scripts) was the actual source of failures here,
    not a real ambiguity it was guarding against. Structural markers
    (fixed UI chrome strings that never wrap) are sufficient and robust.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pane = _capture_pane(socket_path, tmux_target)
        if _kiro_permission_prompt_active(pane) and _kiro_permission_focus_on_one_time_allow(pane):
            return
        time.sleep(_POLL_INTERVAL_S)
    raise RuntimeError(
        "kiro-native permission prompt was not safely focused before verdict delivery"
    )


def _wait_for_focus(
    socket_path: str,
    tmux_target: str,
    *,
    focus_check: Callable[[str], bool],
    timeout_s: float,
    prompt_active_check: Callable[[str], bool] = _kiro_permission_prompt_active,
) -> str:
    """Poll the pane until ``focus_check`` holds; return the last captured pane.

    Every navigation step below (``Down`` then re-check) used to re-capture
    the pane exactly once and give up permanently if that single capture
    didn't show the expected row focused — a plain tmux redraw race (the
    pane captured mid-repaint, before Kiro finished drawing the cursor on
    its new row) was enough to abandon delivery for good, leaving the verdict
    the human already gave stuck forever with no further attempt (see
    ``send_kiro_permission_verdict``). This mirrors the retry loop
    ``_wait_for_kiro_permission_prompt`` already uses to wait for the prompt
    to first appear, applied to each individual focus check instead of just
    the initial one.

    ``prompt_active_check`` defaults to the top-level permission prompt's
    marker check; ``send_kiro_trust_scope_verdict`` passes
    ``_kiro_trust_scope_active`` instead, since it navigates the *submenu*
    Kiro opens after "Trust, always allow" rather than the top-level prompt.
    """
    deadline = time.monotonic() + timeout_s
    pane = ""
    while time.monotonic() < deadline:
        pane = _capture_pane(socket_path, tmux_target)
        if prompt_active_check(pane) and focus_check(pane):
            return pane
        time.sleep(_POLL_INTERVAL_S)
    return pane


def _wait_for_kiro_input_ready(
    socket_path: str,
    tmux_target: str,
    *,
    timeout_s: float,
) -> None:
    """Wait until Kiro has rendered an input prompt before typing.

    Extends the wait to :data:`_KIRO_BOOT_READY_TIMEOUT_S` while kiro's
    "Initializing" banner is still on the pane, so a slow TUI boot delays the
    first turn instead of failing it. A pane that is neither ready nor booting
    still fails at *timeout_s*.
    """
    deadline = time.monotonic() + timeout_s
    boot_deadline = time.monotonic() + max(timeout_s, _KIRO_BOOT_READY_TIMEOUT_S)
    pane = ""
    while time.monotonic() < deadline:
        pane = _capture_pane(socket_path, tmux_target)
        if _kiro_input_ready(pane):
            return
        if _kiro_still_booting(pane) and time.monotonic() < boot_deadline:
            deadline = boot_deadline
        time.sleep(_POLL_INTERVAL_S)
    # A kiro-cli that refused its own argv (e.g. an unsupported flag) leaves the
    # error on the pane and never renders a prompt; quote it so the surfaced
    # failure names the real cause instead of just the readiness timeout.
    raise RuntimeError(
        "kiro-native TUI input prompt was not ready before injection"
        + (f"; kiro terminal showed: {detail}" if (detail := _kiro_pane_error(pane)) else "")
    )


def _kiro_still_booting(pane: str) -> bool:
    """Return whether Kiro's input region shows it is still initializing."""
    region = _kiro_input_region(pane)
    return any(marker in region for marker in _KIRO_BOOT_MARKERS)


def _kiro_pane_error(pane: str) -> str:
    """Return the last error-looking line from the pane, or an empty string."""
    for raw_line in reversed(pane.splitlines()):
        line = raw_line.strip()
        if line.lower().startswith(("error:", "warning: ", "thread '")):
            return line[:200]
    return ""


def _paste_payload_bytes(text: str) -> bytes:
    r"""Encode text for ``tmux load-buffer``: line breaks → CR, tabs kept, other
    control bytes dropped (a stray ESC would close the bracketed-paste early)."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    body = bytearray()
    for ch in normalized:
        if ch == "\n":
            body.append(0x0D)
            continue
        if ch == "\t":
            body.append(0x09)
            continue
        if ord(ch) < 0x20:
            continue
        body.extend(ch.encode("utf-8"))
    return bytes(body)


def _paste_literal_text(socket_path: str, tmux_target: str, bridge_dir: Path, text: str) -> None:
    """Deliver text into Kiro via a tmux bracketed paste (multi-line safe).

    ``send-keys -l`` sends interior newlines as raw Enter keys, so a multi-line
    web message submits line-by-line on the first break. ``load-buffer`` +
    ``paste-buffer -p`` wraps the text in bracketed-paste markers so Kiro's
    composer keeps the line breaks (encoded as CR by :func:`_paste_payload_bytes`)
    as draft data, not submits. Mirrors cursor-native / goose-native; the trailing
    newline absorbs any trailing backslash so it can't escape the follow-up Enter.
    """
    with tempfile.NamedTemporaryFile(
        dir=bridge_dir, prefix="paste_", suffix=".bin", delete=False
    ) as paste_file:
        paste_file.write(_paste_payload_bytes(text + "\n"))
        paste_path = paste_file.name
    try:
        _run_tmux(socket_path, "load-buffer", "-b", _PASTE_BUFFER, paste_path)
        _run_tmux(
            socket_path,
            "paste-buffer",
            "-p",  # bracketed-paste markers — the TUI keeps newlines as data
            "-d",  # drop the buffer after pasting
            "-b",
            _PASTE_BUFFER,
            "-t",
            tmux_target,
        )
    finally:
        with contextlib.suppress(OSError):
            os.unlink(paste_path)


def inject_user_message(
    bridge_dir: Path,
    *,
    content: str,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> None:
    """Deliver a web-UI user message into the Kiro TUI via tmux typing."""
    if not content:
        raise RuntimeError("kiro-native injection requires non-empty content")
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    raw_info = _read_bridge_json(bridge_dir, _TMUX_FILE) or {}
    _wait_for_forwarder_ready_if_required(
        bridge_dir,
        tmux_info=raw_info,
        timeout_s=timeout_s,
    )
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    _wait_for_kiro_input_ready(socket_path, tmux_target, timeout_s=timeout_s)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "C-a")
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "C-k")
    baseline_region = _kiro_input_region(_capture_pane(socket_path, tmux_target))
    _paste_literal_text(socket_path, tmux_target, bridge_dir, content)
    needle = _submit_needle(content)
    draft_seen = False
    if needle:
        deadline = time.monotonic() + _TYPE_COMMIT_TIMEOUT_S
        while time.monotonic() < deadline:
            if _draft_in_input_region(
                _capture_pane(socket_path, tmux_target), needle, baseline_region
            ):
                draft_seen = True
                break
            time.sleep(_POLL_INTERVAL_S)
    time.sleep(_TYPE_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
    if not draft_seen:
        return
    deadline = time.monotonic() + _SUBMIT_VERIFY_TIMEOUT_S
    last_enter = time.monotonic()
    while time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL_S)
        if not _draft_in_input_region(
            _capture_pane(socket_path, tmux_target), needle, baseline_region
        ):
            return
        if time.monotonic() - last_enter >= _SUBMIT_RETRY_INTERVAL_S:
            _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
            last_enter = time.monotonic()
    raise RuntimeError("Kiro did not accept the submitted message; the draft is still visible")


def inject_interrupt(bridge_dir: Path, *, timeout_s: float = _TMUX_READY_TIMEOUT_S) -> None:
    """Cancel the in-flight Kiro turn by sending ``Escape`` to the pane.

    The harness ``run_turn`` returns right after the paste, so the runner's
    in-process cancel floor can't reach the turn — this is the analog of
    :func:`inject_user_message` for the web UI's Stop button. ``Escape`` stops a
    running Kiro turn and (verified against kiro-cli 2.10.0) leaves the composer
    at an empty prompt, so no draft-clear is needed afterwards: unlike
    cursor-native, Kiro does not restore the interrupted prompt. Mirrors
    :func:`omnigent.harnesses.goose_native.bridge.inject_interrupt`.

    :raises RuntimeError: If the tmux target is not advertised or send-keys fails.
    """
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    # No ``-l``: tmux must interpret ``Escape`` as a key name.
    _run_tmux(info["socket_path"], "send-keys", "-t", info["tmux_target"], "Escape")


def kill_session(bridge_dir: Path, *, timeout_s: float = _TMUX_READY_TIMEOUT_S) -> None:
    """Hard-stop the Kiro session by killing its tmux session.

    Terminates ``kiro-cli`` and the pane outright — the analog of the user
    manually exiting the attached TUI, for the web UI's "Stop session"
    affordance. Mirrors :func:`omnigent.harnesses.goose_native.bridge.kill_session`.

    :raises RuntimeError: If the tmux target is not advertised or kill-session fails.
    """
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    _run_tmux(info["socket_path"], "kill-session", "-t", info["tmux_target"])


def send_kiro_permission_verdict(
    bridge_dir: Path,
    *,
    action: str,
    has_trust_always_option: bool = True,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> None:
    """Deliver a one-time or trust-always Kiro permission verdict to the active TUI prompt.

    ``has_trust_always_option`` must reflect whether *this specific* prompt
    offered "Trust, always allow in this session" (i.e.
    ``KiroPermissionRequest.always_option_id is not None``) — it controls how
    many rows "No" sits below the default focus for ``decline``/``cancel``.
    Defaults to ``True`` (the historical, 3-row assumption) for callers that
    don't track this.
    """
    if action not in {"accept", "decline", "cancel", "allow_always"}:
        raise RuntimeError(f"unsupported Kiro permission action: {action!r}")
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    _wait_for_kiro_permission_prompt(socket_path, tmux_target, timeout_s=timeout_s)
    if action == "accept":
        time.sleep(_PERMISSION_ENTER_SETTLE_S)
        pane = _wait_for_focus(
            socket_path,
            tmux_target,
            focus_check=_kiro_permission_focus_on_one_time_allow,
            timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
        )
        if not (
            _kiro_permission_prompt_active(pane) and _kiro_permission_focus_on_one_time_allow(pane)
        ):
            raise RuntimeError("kiro-native allow option was not safely focused before delivery")
        _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
        time.sleep(_PERMISSION_KEY_INTERVAL_S)
        return
    if action == "allow_always":
        # "Trust, always allow in this session" sits one row below the
        # default one-time-allow focus (_wait_for_kiro_permission_prompt
        # above already confirmed the prompt starts there), so a single Down
        # lands on it.
        _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Down")
        time.sleep(_PERMISSION_KEY_INTERVAL_S)
        pane = _wait_for_focus(
            socket_path,
            tmux_target,
            focus_check=_kiro_permission_focus_on_always_allow,
            timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
        )
        if not (
            _kiro_permission_prompt_active(pane) and _kiro_permission_focus_on_always_allow(pane)
        ):
            raise RuntimeError(
                "kiro-native trust-always option was not safely focused before delivery"
            )
        time.sleep(_PERMISSION_ENTER_SETTLE_S)
        _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
        time.sleep(_PERMISSION_KEY_INTERVAL_S)
        return
    # decline / cancel: "No" sits one row below the default one-time-allow
    # focus when Kiro also offered "Trust, always allow" (3-row menu), or
    # directly below it otherwise (2-row menu — see ``has_trust_always_option``).
    # Sending a fixed two Downs regardless used to overshoot "No" on a 2-row
    # menu and land back on nothing recognizable, permanently abandoning the
    # decline instead of just landing correctly.
    down_presses = 2 if has_trust_always_option else 1
    for _ in range(down_presses):
        _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Down")
        time.sleep(_PERMISSION_KEY_INTERVAL_S)
    pane = _wait_for_focus(
        socket_path,
        tmux_target,
        focus_check=_kiro_permission_focus_on_reject,
        timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
    )
    if not (_kiro_permission_prompt_active(pane) and _kiro_permission_focus_on_reject(pane)):
        raise RuntimeError("kiro-native reject option was not safely focused before delivery")
    time.sleep(_PERMISSION_ENTER_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
    time.sleep(_PERMISSION_KEY_INTERVAL_S)


def send_kiro_subagent_permission_verdict(
    bridge_dir: Path,
    *,
    subagent_name: str,
    action: str,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> None:
    """Deliver a one-time accept/decline verdict to *subagent_name*'s own prompt.

    Subagent counterpart of ``send_kiro_permission_verdict``: Kiro V3 batches
    every pending subagent tool-call approval behind one top-level picker
    rather than showing each modally (see ``_focus_kiro_subagent_prompt``),
    so answering one specific subagent's request means drilling into AGENT
    MONITOR and selecting its row first, then using its dedicated "y"/"n"
    shortcuts instead of the top-level Down/Enter picker navigation.

    ``action`` must be "accept", "decline", or "cancel" — for "allow_always"
    use :func:`navigate_to_kiro_subagent_trust_scope` instead, since that
    verdict may open a further trust-scope submenu this function doesn't
    handle.

    :raises RuntimeError: if the tmux target is stale, the TUI has exited,
        *subagent_name*'s prompt is never reached (see
        ``_focus_kiro_subagent_prompt``), or the prompt is still showing
        after the keystroke (delivery not confirmed).
    """
    if action not in {"accept", "decline", "cancel"}:
        raise RuntimeError(f"unsupported kiro subagent permission action: {action!r}")
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    _focus_kiro_subagent_prompt(
        socket_path, tmux_target, subagent_name=subagent_name, timeout_s=timeout_s
    )
    key = "y" if action == "accept" else "n"
    time.sleep(_PERMISSION_ENTER_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, key)
    time.sleep(_PERMISSION_KEY_INTERVAL_S)
    pane = _wait_for_focus(
        socket_path,
        tmux_target,
        focus_check=lambda p: not _kiro_agent_monitor_subagent_focused(p, subagent_name),
        timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
        prompt_active_check=lambda _p: True,
    )
    if _kiro_agent_monitor_subagent_focused(pane, subagent_name):
        raise RuntimeError(
            f"kiro-native subagent {subagent_name!r} verdict delivery was not confirmed"
        )


def navigate_to_kiro_subagent_trust_scope(
    bridge_dir: Path,
    *,
    subagent_name: str,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> list[str]:
    """Select "Trust, always allow" for *subagent_name* and report any trust-scope submenu.

    Subagent counterpart of ``navigate_to_kiro_trust_scope``: reaches
    *subagent_name*'s own prompt in AGENT MONITOR first (see
    ``_focus_kiro_subagent_prompt``), then uses its dedicated "t" trust
    shortcut instead of the top-level Down-navigate-to-third-row dance.
    Kiro's trust-scope submenu, once open, renders with the same markers
    regardless of which prompt opened it (confirmed against a live subagent
    prompt), so the resulting rows are finished the same way as the
    top-level flow: via :func:`send_kiro_trust_scope_verdict`.

    Returns an empty list if the prompt instead resolves directly with no
    submenu — not every prompt kind offers scoped trust (observed: MCP
    tools resolve directly; native shell commands open the submenu).

    :raises RuntimeError: if *subagent_name*'s prompt is never reached, or if
        neither the submenu nor prompt resolution is observed before
        *timeout_s*.
    """
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    _focus_kiro_subagent_prompt(
        socket_path, tmux_target, subagent_name=subagent_name, timeout_s=timeout_s
    )
    time.sleep(_PERMISSION_ENTER_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "t")
    time.sleep(_PERMISSION_KEY_INTERVAL_S)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pane = _capture_pane(socket_path, tmux_target)
        if _kiro_trust_scope_active(pane):
            return _kiro_trust_scope_rows(pane)
        if not _kiro_agent_monitor_subagent_focused(pane, subagent_name):
            # Resolved directly — this prompt kind has no trust-scope submenu.
            return []
        time.sleep(_POLL_INTERVAL_S)
    raise RuntimeError(
        "kiro-native subagent trust-scope submenu did not appear and the "
        "prompt did not resolve after selecting trust-always"
    )


def navigate_to_kiro_trust_scope(
    bridge_dir: Path,
    *,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> list[str]:
    """Select "Trust, always allow" and report the trust-scope submenu it opens.

    Some prompt kinds (observed: shell) don't complete the trust-always
    verdict on this Enter — Kiro instead opens a second, local-only submenu
    asking exactly what to trust (e.g. "Full command" / "Partial command" /
    "Base command" / "Entire tool" — see ``_kiro_trust_scope_rows``). This
    performs that first navigation step and returns the submenu's rows
    verbatim so a caller (``kiro_native_permissions.py``) can ask a human
    which one to pick, then finish the flow via
    ``send_kiro_trust_scope_verdict``.

    Returns an empty list if the prompt instead resolves directly with no
    submenu (no further action needed) — not every prompt kind is known to
    offer scoped trust, and treating "no submenu appeared" as an error would
    wrongly fail prompt kinds that simply don't have one.

    :raises RuntimeError: if the top-level prompt is never safely focused on
        "Trust, always allow", or if neither the submenu nor prompt
        resolution is observed before *timeout_s*.
    """
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    _wait_for_kiro_permission_prompt(socket_path, tmux_target, timeout_s=timeout_s)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Down")
    time.sleep(_PERMISSION_KEY_INTERVAL_S)
    pane = _wait_for_focus(
        socket_path,
        tmux_target,
        focus_check=_kiro_permission_focus_on_always_allow,
        timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
    )
    if not (_kiro_permission_prompt_active(pane) and _kiro_permission_focus_on_always_allow(pane)):
        raise RuntimeError(
            "kiro-native trust-always option was not safely focused before delivery"
        )
    time.sleep(_PERMISSION_ENTER_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
    time.sleep(_PERMISSION_KEY_INTERVAL_S)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pane = _capture_pane(socket_path, tmux_target)
        if _kiro_trust_scope_active(pane):
            return _kiro_trust_scope_rows(pane)
        if not _kiro_permission_prompt_active(pane):
            # The whole prompt resolved directly — this prompt kind has no
            # trust-scope submenu.
            return []
        time.sleep(_POLL_INTERVAL_S)
    raise RuntimeError(
        "kiro-native trust-scope submenu did not appear and the prompt did not "
        "resolve after selecting trust-always"
    )


def send_kiro_trust_scope_verdict(
    bridge_dir: Path,
    *,
    option_index: int,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> None:
    """Complete a pending trust-scope submenu by selecting ``option_index``.

    ``option_index`` is 0-based, in the on-screen order returned by
    ``navigate_to_kiro_trust_scope`` — that call must have already opened
    this submenu for the same session; this only finishes it.
    """
    if option_index < 0:
        raise RuntimeError(f"invalid kiro trust-scope option_index: {option_index!r}")
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _kiro_trust_scope_active(_capture_pane(socket_path, tmux_target)):
            break
        time.sleep(_POLL_INTERVAL_S)
    else:
        raise RuntimeError(
            "kiro-native trust-scope submenu was not visible before verdict delivery"
        )
    for _ in range(option_index):
        _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Down")
        time.sleep(_PERMISSION_KEY_INTERVAL_S)
    pane = _wait_for_focus(
        socket_path,
        tmux_target,
        focus_check=lambda p: _kiro_trust_scope_focused_index(p) == option_index,
        timeout_s=_PERMISSION_FOCUS_RETRY_TIMEOUT_S,
        prompt_active_check=_kiro_trust_scope_active,
    )
    if _kiro_trust_scope_focused_index(pane) != option_index:
        raise RuntimeError("kiro-native trust-scope option was not safely focused before delivery")
    time.sleep(_PERMISSION_ENTER_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
    time.sleep(_PERMISSION_KEY_INTERVAL_S)


# kiro prints "Model changed to <id> (saved as default)" after a successful
# ``/model`` switch; the injector polls for this to confirm the switch landed.
_MODEL_CHANGED_MARKER = "Model changed to"
# The switch itself takes a couple of seconds (kiro round-trips the change), so
# the confirmation poll uses its own timeout rather than the short pane-readiness
# ``timeout_s`` the runner passes to fail fast when the pane isn't attached.
_MODEL_CONFIRM_TIMEOUT_S = 10.0


def inject_model_command(
    bridge_dir: Path,
    *,
    model: str,
    timeout_s: float = _TMUX_READY_TIMEOUT_S,
) -> None:
    """Switch the live kiro model by typing ``/model <id>`` into the TUI.

    kiro-cli's ``--model`` is baked in at spawn, so a mid-session web pick can't
    be applied by re-reading the persisted ``model_override`` — it has to be
    typed into the running pane. kiro's ``/model <id>`` switches directly (no
    picker) and prints ``Model changed to <id>``; poll for that so a typo'd or
    unavailable id fails loudly rather than silently leaving the model unchanged.
    The cursor-native analog is
    :func:`omnigent.harnesses.cursor_native.bridge.inject_model_command`.

    Note: kiro persists the switch as its own global default ("saved as
    default"), so a live switch also affects the next fresh kiro launch.

    :param bridge_dir: The kiro-native bridge dir holding ``tmux.json``.
    :param model: kiro model id, e.g. ``"claude-haiku-4.5"`` (a ``--list-models`` id).
    :param timeout_s: Per-readiness-gate / confirmation timeout.
    :raises RuntimeError: If the tmux target is never advertised, the TUI has
        exited, a tmux command fails, or kiro never confirms the switch.
    """
    model = model.strip()
    if not model:
        raise RuntimeError("kiro-native model switch requires a non-empty model id")
    info = _wait_for_tmux_info(bridge_dir, timeout_s=timeout_s)
    socket_path = info["socket_path"]
    tmux_target = info["tmux_target"]
    if not _session_alive(socket_path, tmux_target):
        raise RuntimeError(
            "kiro terminal is no longer running (the TUI exited); restart the session"
        )
    _wait_for_kiro_input_ready(socket_path, tmux_target, timeout_s=timeout_s)
    # Clear any leftover draft so the slash command isn't appended to it.
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "C-a")
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "C-k")
    # ``-l`` sends literal characters so ``/`` opens the slash command and the id
    # is not parsed as tmux key names.
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "-l", f"/model {model}")
    time.sleep(_TYPE_SETTLE_S)
    _run_tmux(socket_path, "send-keys", "-t", tmux_target, "Enter")
    # Confirm via kiro's "Model changed to <id>" line so a bad id fails loudly.
    deadline = time.monotonic() + _MODEL_CONFIRM_TIMEOUT_S
    while time.monotonic() < deadline:
        if f"{_MODEL_CHANGED_MARKER} {model}" in _capture_pane(socket_path, tmux_target):
            return
        time.sleep(_POLL_INTERVAL_S)
    raise RuntimeError(f"kiro-native did not confirm the model switch to {model!r}")
