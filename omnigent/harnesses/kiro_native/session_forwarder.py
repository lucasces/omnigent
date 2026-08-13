"""Structured session forwarder for the kiro-native harness.

Kiro CLI persists chat turns under ``~/.kiro/sessions/cli`` as session metadata
plus JSONL message records. The native Kiro terminal path injects web prompts
into the TUI; this forwarder mirrors Kiro's persisted assistant messages —
plus any ``toolUse``/``toolResult`` blocks they carry — back into the
Omnigent conversation with ``external_conversation_item`` events (as
``message``, ``function_call``, and ``function_call_output`` items
respectively — the same item types ``claude_native_bridge.py`` uses for
Claude Code). Without the tool-call/result mirroring, a Kiro command's only
trace in the web UI was the fleeting approval-dialog preview: gone for good
once the elicitation resolved and the conversation reloaded, and never
surfaced its own tool-card spinner while running.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from omnigent.harnesses.kiro_native.bridge import write_forwarder_ready

_logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL_S = 0.7
_POST_TIMEOUT_S = 30.0
_DISCOVERY_SKEW_MS = 10_000
_STATE_FILE = "kiro_session_forwarder.json"

_SUPERVISOR_INITIAL_BACKOFF_S = 1.0
_SUPERVISOR_MAX_BACKOFF_S = 30.0
_SUPERVISOR_HEALTHY_UPTIME_S = 60.0


@dataclass
class _ForwardState:
    """Durable cursor for one Kiro JSONL session file."""

    session_id: str | None = None
    byte_offset: int = 0


@dataclass(frozen=True)
class KiroConversationMessage:
    """Stable parsed-message contract shared by forwarding and offline import."""

    message_id: str
    role: str
    text: str


_KiroConversationMessage = KiroConversationMessage


@dataclass(frozen=True)
class KiroToolCall:
    """One ``toolUse`` block pulled out of a Kiro ``AssistantMessage`` record.

    Forwarded as a ``function_call`` item so the command gets a durable,
    reload-surviving record and its own tool-card spinner in the UI, instead
    of being visible only in the transient approval-dialog preview.
    """

    message_id: str
    call_id: str
    name: str
    arguments: dict[str, object]


@dataclass(frozen=True)
class KiroToolResult:
    """One ``toolResult`` block pulled out of a Kiro ``ToolResults`` record."""

    message_id: str
    call_id: str
    output: str


KiroForwardItem = KiroConversationMessage | KiroToolCall | KiroToolResult


def kiro_cli_sessions_dir(home: Path | None = None) -> Path:
    """Return Kiro CLI's session directory for this user."""
    return (home or Path.home()) / ".kiro" / "sessions" / "cli"


_kiro_cli_sessions_dir = kiro_cli_sessions_dir


def _read_state(bridge_dir: Path) -> _ForwardState:
    """Load the persisted forward cursor, or a cold default."""
    try:
        data = json.loads((bridge_dir / _STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _ForwardState()
    session_id = data.get("session_id")
    byte_offset = data.get("byte_offset")
    return _ForwardState(
        session_id=session_id if isinstance(session_id, str) and session_id else None,
        byte_offset=byte_offset if isinstance(byte_offset, int) and byte_offset >= 0 else 0,
    )


def _write_state(bridge_dir: Path, state: _ForwardState) -> None:
    """Persist the forward cursor atomically."""
    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(bridge_dir, 0o700)
    tmp = bridge_dir / (_STATE_FILE + ".tmp")
    tmp.write_text(
        json.dumps({"session_id": state.session_id, "byte_offset": state.byte_offset}),
        encoding="utf-8",
    )
    os.replace(tmp, bridge_dir / _STATE_FILE)


def _parse_iso_epoch_ms(value: object) -> int:
    """Parse Kiro's ISO timestamp string into epoch milliseconds."""
    if not isinstance(value, str) or not value:
        return 0
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def _same_workspace(left: object, right: str) -> bool:
    """Return whether Kiro metadata cwd matches the runner workspace."""
    if not isinstance(left, str) or not left:
        return False
    try:
        return Path(left).expanduser().resolve() == Path(right).expanduser().resolve()
    except OSError:
        return left == right


# Competing-candidate sets already warned about, so the ambiguous branch logs
# once per distinct collision instead of every poll tick for the session's life.
# ponytail: grows by one entry per distinct concurrent collision — too rare to
# bound; add a cap only if a pathological churn ever shows up.
_ambiguous_discovery_warned: set[frozenset[str]] = set()


def _warn_ambiguous_discovery(workspace: str, session_ids: list[str]) -> None:
    """Warn once per distinct set of competing same-workspace Kiro sessions.

    Discovery returns ``None`` for both "no candidate yet" (transient) and ">=2
    candidates" (won't ever bind until one goes away). This makes the latter
    diagnosable without flooding logs on every ~0.7s poll.
    """
    key = frozenset(session_ids)
    if key in _ambiguous_discovery_warned:
        return
    _ambiguous_discovery_warned.add(key)
    _logger.warning(
        "kiro session discovery ambiguous; %d same-workspace sessions above the "
        "launch floor, binding none to avoid cross-talk; workspace=%s sessions=%s",
        len(session_ids),
        workspace,
        sorted(session_ids),
    )


def _discover_kiro_session_jsonl(
    *,
    workspace: str,
    launch_epoch_ms: int,
    sessions_dir: Path | None = None,
) -> tuple[str, Path] | None:
    """Find this Omnigent session's Kiro JSONL file — only when it's unambiguous.

    Candidates are Kiro sessions in the same workspace (``cwd``) with a parseable
    ``created_at`` at/after the launch floor (``launch_epoch_ms`` minus a small
    skew, which already drops pre-existing sessions). We bind **only when exactly
    one** session qualifies.

    Each Kiro session is its own JSONL keyed by Kiro's minted id, so two fresh
    sessions launched in the same workspace within the skew window both qualify.
    Picking newest-by-``updated_at`` (the old behaviour) would latch onto
    whichever session most recently emitted a turn — i.e. it can bind the *other*
    session's transcript and silently cross-talk it into this conversation. With
    two or more candidates we can't tell which JSONL is ours, so we return
    ``None`` and retry rather than guess (logged once via
    :func:`_warn_ambiguous_discovery` so the ambiguous case is distinct from "not
    written yet"). A brief delay is safe; mirroring the wrong conversation is not.
    Mirrors cursor-native's "bind only when exactly one chat qualifies"
    (:func:`omnigent.harnesses.cursor_native.forwarder._discover_store`).

    The resume/fork path doesn't reach here: when the Kiro id is already known the
    caller binds it directly via :func:`_kiro_session_jsonl_for_id`.
    """
    root = sessions_dir or kiro_cli_sessions_dir()
    if not root.is_dir():
        return None
    floor_ms = max(0, launch_epoch_ms - _DISCOVERY_SKEW_MS)
    candidates: list[tuple[str, Path]] = []
    for metadata_path in root.glob("*.json"):
        session_id = metadata_path.stem
        jsonl_path = root / f"{session_id}.jsonl"
        if not jsonl_path.is_file():
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(metadata, dict) or not _same_workspace(metadata.get("cwd"), workspace):
            continue
        created_ms = _parse_iso_epoch_ms(metadata.get("created_at"))
        # Require a parseable created_at at/after the floor. A fresh session always
        # stamps created_at, so a missing/garbled one can't be confirmed in-window;
        # dropping it stops an undateable straggler from poisoning the "exactly one"
        # count and silently blocking discovery forever.
        if not created_ms or created_ms < floor_ms:
            continue
        candidates.append((session_id, jsonl_path))
    if len(candidates) > 1:
        _warn_ambiguous_discovery(workspace, [session_id for session_id, _ in candidates])
        return None
    return candidates[0] if candidates else None


def _kiro_session_jsonl_for_id(
    session_id: str,
    *,
    workspace: str,
    sessions_dir: Path | None = None,
) -> Path | None:
    """Return the JSONL path for a known Kiro session id, if it is usable."""
    root = sessions_dir or kiro_cli_sessions_dir()
    metadata_path = root / f"{session_id}.json"
    jsonl_path = root / f"{session_id}.jsonl"
    if not jsonl_path.is_file():
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(metadata, dict) or not _same_workspace(metadata.get("cwd"), workspace):
        return None
    return jsonl_path


def _read_new_kiro_messages(
    jsonl_path: Path,
    byte_offset: int,
) -> tuple[list[KiroForwardItem], int]:
    """Read forwardable items after *byte_offset* from Kiro's JSONL file.

    Items are messages, tool calls, and tool results (see
    :func:`_parse_kiro_jsonl_line_items`) — despite the name, this has
    covered more than plain conversation messages since tool-call mirroring
    was added; kept for the stable call sites/tests that already reference
    it.
    """
    items: list[KiroForwardItem] = []
    try:
        with jsonl_path.open("rb") as handle:
            handle.seek(byte_offset)
            # Advance only past newline-terminated lines: Kiro appends to this
            # JSONL live, so the final line may be a record mid-write (no
            # trailing ``\n``). Persisting ``handle.tell()`` past such a partial
            # line would skip the record once Kiro finishes writing it. Hold the
            # offset at the last complete line and re-read the tail next poll.
            offset = byte_offset
            for raw_line in handle:
                if not raw_line.endswith(b"\n"):
                    break
                offset += len(raw_line)
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                items.extend(_parse_kiro_jsonl_line_items(line))
            return items, offset
    except OSError:
        return [], byte_offset


def parse_kiro_jsonl_line(line: str) -> KiroConversationMessage | None:
    """Parse one Kiro JSONL line into the stable shared message contract."""
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    kind = record.get("kind")
    if kind == "Prompt":
        role = "user"
    elif kind == "AssistantMessage":
        role = "assistant"
    else:
        return None
    data = record.get("data")
    if not isinstance(data, dict):
        return None
    message_id = data.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return None
    text = _kiro_content_text(data.get("content")).strip()
    if not text:
        return None
    return KiroConversationMessage(message_id=message_id, role=role, text=text)


_parse_kiro_jsonl_line = parse_kiro_jsonl_line


def _kiro_content_text(content: object) -> str:
    """Join text blocks from Kiro's persisted message content.

    Tool results are the main consumer of the ``kind: "json"`` branch: a
    shell/gh/grep tool result comes back from Kiro as
    ``{"kind": "json", "data": {"exit_status": ..., "stdout": ..., "stderr":
    ...}}`` (or another tool-specific shape), never as ``kind: "text"``. In a
    real transcript sample, 243 of 350 tool results were this shape — treating
    only ``kind: "text"`` as content silently turned the majority of mirrored
    Kiro tool-call outputs into empty strings. Falls back to a compact JSON
    dump, the same non-string-content handling
    ``claude_native_bridge._tool_result_output`` uses for Claude's tool
    results.
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("kind") == "text" and isinstance(block.get("data"), str):
            parts.append(block["data"])
        elif block.get("type") in {"text", "output_text"} and isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif block.get("kind") == "json" and "data" in block:
            parts.append(json.dumps(block["data"], ensure_ascii=False, separators=(",", ":")))
    return "\n".join(parts)


def _parse_kiro_jsonl_line_items(line: str) -> list[KiroForwardItem]:
    """Parse one Kiro JSONL line into every forwardable item it carries.

    Unlike :func:`parse_kiro_jsonl_line` (text-only, the stable contract
    shared with offline import), this also surfaces ``toolUse``/
    ``toolResult`` blocks so the live forwarder can mirror them as durable
    ``function_call``/``function_call_output`` items. A single
    ``AssistantMessage`` record commonly carries both narration text and one
    or more ``toolUse`` blocks in the same turn, so this returns a list.
    """
    try:
        record = json.loads(line)
    except ValueError:
        return []
    if not isinstance(record, dict):
        return []
    data = record.get("data")
    if not isinstance(data, dict):
        return []
    message_id = data.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return []
    kind = record.get("kind")
    if kind == "Prompt":
        text = _kiro_content_text(data.get("content")).strip()
        if not text:
            return []
        return [KiroConversationMessage(message_id=message_id, role="user", text=text)]
    if kind == "AssistantMessage":
        return _kiro_assistant_message_items(message_id, data.get("content"))
    if kind == "ToolResults":
        return _kiro_tool_result_items(message_id, data.get("content"))
    return []


def _kiro_assistant_message_items(message_id: str, content: object) -> list[KiroForwardItem]:
    """Split one AssistantMessage's content blocks into text + toolUse items."""
    if not isinstance(content, list):
        return []
    items: list[KiroForwardItem] = []
    text = _kiro_content_text(content).strip()
    if text:
        items.append(KiroConversationMessage(message_id=message_id, role="assistant", text=text))
    for block in content:
        if not isinstance(block, dict) or block.get("kind") != "toolUse":
            continue
        tool_data = block.get("data")
        if not isinstance(tool_data, dict):
            continue
        call_id = tool_data.get("toolUseId")
        name = tool_data.get("name")
        if not isinstance(call_id, str) or not call_id:
            continue
        if not isinstance(name, str) or not name:
            continue
        arguments = tool_data.get("input")
        if not isinstance(arguments, dict):
            arguments = {}
        items.append(
            KiroToolCall(message_id=message_id, call_id=call_id, name=name, arguments=arguments)
        )
    return items


def _kiro_tool_result_items(message_id: str, content: object) -> list[KiroForwardItem]:
    """Extract toolResult blocks from one ToolResults record.

    Non-text results (e.g. an image tool result) forward with an empty
    ``output`` — there is no text to mirror, but the call still gets its
    durable, matched-by-``call_id`` output item instead of being left to
    look forever "still running" in the UI.
    """
    if not isinstance(content, list):
        return []
    items: list[KiroForwardItem] = []
    for block in content:
        if not isinstance(block, dict) or block.get("kind") != "toolResult":
            continue
        result_data = block.get("data")
        if not isinstance(result_data, dict):
            continue
        call_id = result_data.get("toolUseId")
        if not isinstance(call_id, str) or not call_id:
            continue
        output = _kiro_content_text(result_data.get("content")).strip()
        items.append(KiroToolResult(message_id=message_id, call_id=call_id, output=output))
    return items


async def _post_conversation_message(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    agent_name: str,
    message: KiroConversationMessage,
) -> None:
    """POST one Kiro message as an external conversation item."""
    if message.role == "assistant":
        item_data = {
            "role": "assistant",
            "agent": agent_name,
            "content": [{"type": "output_text", "text": message.text}],
        }
    else:
        item_data = {
            "role": "user",
            "content": [{"type": "input_text", "text": message.text}],
        }
    resp = await client.post(
        f"/v1/sessions/{session_id}/events",
        json={
            "type": "external_conversation_item",
            "data": {
                "item_type": "message",
                "item_data": item_data,
                "response_id": f"kiro:{message.message_id}",
            },
        },
    )
    resp.raise_for_status()


async def _post_kiro_tool_call(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    agent_name: str,
    call: KiroToolCall,
) -> None:
    """POST one Kiro tool invocation as a persisted ``function_call`` item.

    Same item type/shape ``claude_native_bridge.py`` posts for Claude Code's
    ``tool_use`` blocks — the web UI's tool-card rendering and call/result
    matching by ``call_id`` already handle it generically.
    """
    resp = await client.post(
        f"/v1/sessions/{session_id}/events",
        json={
            "type": "external_conversation_item",
            "data": {
                "item_type": "function_call",
                "item_data": {
                    "agent": agent_name,
                    "name": call.name,
                    "arguments": json.dumps(call.arguments, separators=(",", ":")),
                    "call_id": call.call_id,
                },
                "response_id": f"kiro:{call.message_id}",
            },
        },
    )
    resp.raise_for_status()


async def _post_kiro_tool_result(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    result: KiroToolResult,
) -> None:
    """POST one Kiro tool result as a persisted ``function_call_output`` item."""
    resp = await client.post(
        f"/v1/sessions/{session_id}/events",
        json={
            "type": "external_conversation_item",
            "data": {
                "item_type": "function_call_output",
                "item_data": {
                    "call_id": result.call_id,
                    "output": result.output,
                },
                "response_id": f"kiro:{result.message_id}",
            },
        },
    )
    resp.raise_for_status()


async def _post_external_session_status(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    status: str,
    response_id: str | None = None,
) -> None:
    """POST one ``external_session_status`` event to the Sessions API.

    Same contract ``hermes_native_forwarder.py`` uses (#1874): when
    *response_id* is given, the edge carries it, and the server keys the live
    tool-call card off a ``running`` edge whose ``response_id`` matches the
    mirrored item's ``response_id`` — reasserting this each poll while a call
    is in-flight keeps the card (and the turn-working indicator) live through
    a long, quiet command that the PTY-activity watcher's ~1s idle threshold
    would otherwise settle within a second. Only ``"running"`` is ever posted
    here; unlike hermes, this forwarder does not take ``idle`` ownership —
    that stays with the PTY watcher, avoiding the double-sourcing #1137 was
    about.

    :raises httpx.HTTPError: If the Omnigent request fails or is rejected.
    """
    data: dict[str, object] = {"status": status}
    if response_id is not None:
        data["response_id"] = response_id
    resp = await client.post(
        f"/v1/sessions/{session_id}/events",
        json={"type": "external_session_status", "data": data},
    )
    resp.raise_for_status()


async def _patch_external_session_id(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    external_session_id: str,
) -> None:
    """Persist Kiro's native CLI session id onto the Omnigent session."""
    resp = await client.patch(
        f"/v1/sessions/{session_id}",
        json={"external_session_id": external_session_id},
    )
    # The server rejects overwrites with a different id. Forwarding must keep
    # running in that case; losing chat mirroring would be worse than failing to
    # improve cold resume for an already-conflicted session.
    if resp.status_code >= 400:
        _logger.warning(
            "AP rejected Kiro external_session_id PATCH (%s); session=%s kiro_session=%s",
            resp.status_code,
            session_id,
            external_session_id,
        )
        return


def _read_kiro_cumulative_credits(metadata_path: Path) -> tuple[float | None, str | None]:
    """Sum the per-turn credit metering from a Kiro session ``.json`` snapshot.

    kiro-cli meters in credits, not tokens: each turn under
    ``session_state.conversation_metadata.user_turn_metadatas`` carries a
    ``metering_usage`` list of ``{"value": <float>, "unit": "credit"}`` entries
    (token counts are 0), and the CLI shows a per-turn ``Credits:`` line. The
    cumulative session cost is the sum of every turn's credit values. This data
    lives only in the ``.json`` snapshot, not the ``.jsonl`` transcript the
    forwarder tails.

    :returns: ``(cumulative_credits, model_id)``, or ``(None, None)`` when the
        file is missing/unparseable or carries no metering yet.
    """
    try:
        raw = metadata_path.read_text(encoding="utf-8")
    except OSError:
        return None, None
    try:
        data = json.loads(raw)
    except ValueError:
        return None, None
    if not isinstance(data, dict):
        return None, None
    session_state = data.get("session_state")
    if not isinstance(session_state, dict):
        return None, None
    conversation_metadata = session_state.get("conversation_metadata")
    turns = (
        conversation_metadata.get("user_turn_metadatas")
        if isinstance(conversation_metadata, dict)
        else None
    )
    if not isinstance(turns, list):
        return None, None
    total = 0.0
    saw_credit = False
    for turn in turns:
        if not isinstance(turn, dict):
            continue
        metering = turn.get("metering_usage")
        if not isinstance(metering, list):
            continue
        for entry in metering:
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if isinstance(value, int | float) and not isinstance(value, bool):
                total += float(value)
                saw_credit = True
    if not saw_credit:
        return None, None
    model_id: str | None = None
    rts_model_state = session_state.get("rts_model_state")
    if isinstance(rts_model_state, dict):
        model_info = rts_model_state.get("model_info")
        if isinstance(model_info, dict):
            candidate = model_info.get("model_id")
            if isinstance(candidate, str) and candidate:
                model_id = candidate
    return total, model_id


def _read_kiro_current_model(metadata_path: Path) -> str | None:
    """Return kiro's current model id from the session ``.json`` snapshot.

    Reads ``session_state.rts_model_state.model_info.model_id`` (e.g. ``"auto"``
    or ``"claude-haiku-4.5"``), independent of the metering read above so it is
    available at launch before any turn. kiro updates it in place on a ``/model``
    switch, so polling it mirrors both the launched model and live TUI switches.

    :returns: The model id, or ``None`` when the file is missing/unparseable or
        carries no model state yet.
    """
    try:
        raw = metadata_path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    session_state = data.get("session_state")
    if not isinstance(session_state, dict):
        return None
    rts_model_state = session_state.get("rts_model_state")
    if not isinstance(rts_model_state, dict):
        return None
    model_info = rts_model_state.get("model_info")
    if not isinstance(model_info, dict):
        return None
    model_id = model_info.get("model_id")
    return model_id if isinstance(model_id, str) and model_id else None


async def _post_external_model_change(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    model: str,
) -> None:
    """Mirror kiro's current model to the web as ``external_model_change``.

    The server persists this as ``model_override`` (so the picker shows the real
    model instead of falling back to the harness name) and deliberately does NOT
    forward a ``/model`` back to the runner, so mirroring the model the TUI is
    already on cannot loop. Mirrors cursor-native's terminal->web model mirror.
    """
    resp = await client.post(
        f"/v1/sessions/{session_id}/events",
        json={"type": "external_model_change", "data": {"model": model}},
    )
    resp.raise_for_status()


async def _post_session_cost(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    cumulative_cost_usd: float,
    model: str | None,
) -> None:
    """POST Kiro's cumulative credit spend as authoritative session cost.

    kiro-cli reports cost in credits and there is no credit->USD conversion
    available, so credits are forwarded 1:1 into ``cumulative_cost_usd`` (the
    same convention the Copilot relay uses for its AI-credit total). The server
    treats this value as authoritative and monotonic, in preference to
    token x catalog pricing, via the ``external_session_usage`` event used by
    the claude-/codex-native forwarders.
    """
    data: dict[str, object] = {"cumulative_cost_usd": cumulative_cost_usd}
    if model:
        data["model"] = model
    resp = await client.post(
        f"/v1/sessions/{session_id}/events",
        json={"type": "external_session_usage", "data": data},
    )
    resp.raise_for_status()


async def forward_kiro_session_to_omnigent(
    *,
    base_url: str,
    headers: dict[str, str],
    session_id: str,
    bridge_dir: Path,
    agent_name: str,
    workspace: str,
    launch_epoch_ms: int,
    expected_session_id: str | None = None,
    poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
    auth: httpx.Auth | None = None,
) -> None:
    """Tail Kiro's session JSONL and mirror assistant messages into AP."""
    state = _read_state(bridge_dir)
    jsonl_path: Path | None = None
    timeout = httpx.Timeout(_POST_TIMEOUT_S)
    mirrored_external_session_id: str | None = None
    last_posted_cost: float | None = None
    last_posted_model: str | None = None
    from omnigent.cli_auth import open_server_client

    # Tracks tool calls posted (as ``function_call`` items) whose matching
    # ``function_call_output`` hasn't arrived yet, keyed by the owning
    # AssistantMessage's ``message_id`` (the same id used as the calls'
    # ``response_id``, ``f"kiro:{message_id}"``). Reset on process restart —
    # acceptable, since a restart mid-call just means the PTY watcher's own
    # idle heuristic (the pre-existing behavior) takes back over for that one
    # call instead of this reassertion. See the reassertion loop below for why
    # this exists.
    pending_calls_by_message: dict[str, set[str]] = {}
    # Reverse index for resolving a KiroToolResult (which carries only the
    # ``call_id``) back to the message_id whose pending set it should clear.
    call_id_to_message: dict[str, str] = {}
    async with open_server_client(base_url, headers=headers, auth=auth, timeout=timeout) as client:
        while True:
            try:
                if state.session_id is None or jsonl_path is None or not jsonl_path.exists():
                    discovered: tuple[str, Path] | None = None
                    if expected_session_id:
                        expected_path = await asyncio.to_thread(
                            _kiro_session_jsonl_for_id,
                            expected_session_id,
                            workspace=workspace,
                        )
                        if expected_path is not None:
                            discovered = (expected_session_id, expected_path)
                    elif discovered is None:
                        discovered = await asyncio.to_thread(
                            _discover_kiro_session_jsonl,
                            workspace=workspace,
                            launch_epoch_ms=launch_epoch_ms,
                        )
                    if discovered is not None:
                        discovered_session_id, discovered_path = discovered
                        if state.session_id != discovered_session_id:
                            state = _ForwardState(session_id=discovered_session_id, byte_offset=0)
                            _write_state(bridge_dir, state)
                        jsonl_path = discovered_path
                if jsonl_path is not None and state.session_id is not None:
                    if mirrored_external_session_id != state.session_id:
                        await _patch_external_session_id(
                            client,
                            session_id=session_id,
                            external_session_id=state.session_id,
                        )
                        mirrored_external_session_id = state.session_id
                    items, byte_offset = await asyncio.to_thread(
                        _read_new_kiro_messages,
                        jsonl_path,
                        state.byte_offset,
                    )
                    for item in items:
                        # Mirror the transcript. Turn-level running/idle status
                        # for kiro-native is still owned by the PTY watcher's
                        # ``emit_status`` (``runner/resource_registry.py``),
                        # matching the other forwarder-backed native harnesses
                        # (goose/qwen) — this forwarder never posts an ``idle``
                        # edge, avoiding the double-sourcing that #1137 was
                        # about. It DOES reassert a response_id-scoped
                        # ``running`` edge below while a tool call is
                        # in-flight, the same technique
                        # hermes_native_forwarder.py uses (#1874): the PTY
                        # watcher's ~1s pane-quiet idle threshold can't tell a
                        # genuinely finished turn from a long, quiet command
                        # (a poll loop, a slow API call, a pending approval
                        # prompt) — without this, such a command settles the
                        # live tool card and the turn-working indicator within
                        # a second of starting, even though the command (and
                        # the turn) is still very much running.
                        if isinstance(item, KiroConversationMessage):
                            await _post_conversation_message(
                                client,
                                session_id=session_id,
                                agent_name=agent_name,
                                message=item,
                            )
                        elif isinstance(item, KiroToolCall):
                            await _post_kiro_tool_call(
                                client,
                                session_id=session_id,
                                agent_name=agent_name,
                                call=item,
                            )
                            call_id_to_message[item.call_id] = item.message_id
                            pending_calls_by_message.setdefault(item.message_id, set()).add(
                                item.call_id
                            )
                        else:
                            await _post_kiro_tool_result(
                                client,
                                session_id=session_id,
                                result=item,
                            )
                            owning_message_id = call_id_to_message.pop(item.call_id, None)
                            if owning_message_id is not None:
                                pending = pending_calls_by_message.get(owning_message_id)
                                if pending is not None:
                                    pending.discard(item.call_id)
                                    if not pending:
                                        del pending_calls_by_message[owning_message_id]
                    for pending_message_id in list(pending_calls_by_message):
                        await _post_external_session_status(
                            client,
                            session_id=session_id,
                            status="running",
                            response_id=f"kiro:{pending_message_id}",
                        )
                    if byte_offset != state.byte_offset:
                        state.byte_offset = byte_offset
                        _write_state(bridge_dir, state)
                    write_forwarder_ready(bridge_dir)
                    # Forward kiro's credit metering as authoritative session
                    # cost. It lives in the ``.json`` snapshot (sibling of the
                    # tailed ``.jsonl``), not the transcript, and is cumulative;
                    # the server treats ``cumulative_cost_usd`` as monotonic, so
                    # only post when it advances.
                    cumulative_cost, cost_model = await asyncio.to_thread(
                        _read_kiro_cumulative_credits, jsonl_path.with_suffix(".json")
                    )
                    if cumulative_cost is not None and (
                        last_posted_cost is None or cumulative_cost > last_posted_cost
                    ):
                        await _post_session_cost(
                            client,
                            session_id=session_id,
                            cumulative_cost_usd=cumulative_cost,
                            model=cost_model,
                        )
                        last_posted_cost = cumulative_cost
                    # Mirror kiro's current model so the web picker shows the real
                    # model (not the harness name) at launch and after a live
                    # ``/model`` switch. Read independently of metering so it is
                    # available before the first turn; posted only when it changes.
                    current_model = await asyncio.to_thread(
                        _read_kiro_current_model, jsonl_path.with_suffix(".json")
                    )
                    if current_model is not None and current_model != last_posted_model:
                        await _post_external_model_change(
                            client, session_id=session_id, model=current_model
                        )
                        last_posted_model = current_model
            except asyncio.CancelledError:
                raise
            except Exception:
                _logger.exception(
                    "kiro session forwarder poll failed; session=%s bridge_dir=%s",
                    session_id,
                    bridge_dir,
                )
            await asyncio.sleep(poll_interval_s)


def _supervisor_monotonic() -> float:
    """Indirection so tests can stub the supervisor clock."""
    return time.monotonic()


async def _supervisor_sleep(seconds: float) -> None:
    """Indirection so tests can stub supervisor sleep."""
    await asyncio.sleep(seconds)


async def supervise_kiro_session_forwarder(
    *,
    base_url: str,
    headers: dict[str, str],
    session_id: str,
    bridge_dir: Path,
    agent_name: str,
    workspace: str,
    launch_epoch_ms: int,
    expected_session_id: str | None = None,
    poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
    auth: httpx.Auth | None = None,
) -> None:
    """Run the Kiro session forwarder under a restart supervisor."""
    backoff_s = _SUPERVISOR_INITIAL_BACKOFF_S
    while True:
        run_started_at = _supervisor_monotonic()
        crash_exc: Exception | None = None
        try:
            await forward_kiro_session_to_omnigent(
                base_url=base_url,
                headers=headers,
                session_id=session_id,
                bridge_dir=bridge_dir,
                agent_name=agent_name,
                workspace=workspace,
                launch_epoch_ms=launch_epoch_ms,
                expected_session_id=expected_session_id,
                poll_interval_s=poll_interval_s,
                auth=auth,
            )
            _logger.warning(
                "kiro session forwarder returned unexpectedly; restarting; "
                "session=%s bridge_dir=%s",
                session_id,
                bridge_dir,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - supervisor restarts on any crash
            crash_exc = exc
        if _supervisor_monotonic() - run_started_at >= _SUPERVISOR_HEALTHY_UPTIME_S:
            backoff_s = _SUPERVISOR_INITIAL_BACKOFF_S
        if crash_exc is not None:
            _logger.error(
                "kiro session forwarder crashed; restarting in %.1fs; session=%s bridge_dir=%s",
                backoff_s,
                session_id,
                bridge_dir,
                exc_info=crash_exc,
            )
        await _supervisor_sleep(backoff_s)
        backoff_s = min(backoff_s * 2, _SUPERVISOR_MAX_BACKOFF_S)


__all__ = [
    "forward_kiro_session_to_omnigent",
    "supervise_kiro_session_forwarder",
]
