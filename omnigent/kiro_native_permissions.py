"""Kiro-native tool-approval mirror (TUI ACP recorder -> web elicitation)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from omnigent.kiro_native_bridge import acp_record_path, send_kiro_permission_verdict

_logger = logging.getLogger(__name__)

_POLL_INTERVAL_S = 0.4
_POST_TIMEOUT_S = 86400.0
_PREVIEW_MAX = 1024
_SUPPORTED_ACCEPT_OPTION = "allow_once"
_SUPPORTED_DECLINE_OPTION = "reject_once"
_SUPPORTED_ALWAYS_OPTION = "allow_always"
# Retry budget for the initial hook POST that parks an approval on the
# server. A transient blip there (observed: a single 502 from the proxy in
# front of the server, pod logs otherwise clean) previously meant the
# elicitation card never got created — Kiro's TUI sat on "thinking" with no
# visible difference from normal work, so a stuck session looked identical
# to a working one. Three attempts with short backoff absorb that class of
# blip silently; only a failure that survives all three is treated as real.
_HOOK_POST_MAX_ATTEMPTS = 3
_HOOK_POST_RETRY_DELAYS_S = (1.0, 3.0)
# Fallback release for a coordinator slot whose keystroke delivery succeeded
# but whose Kiro ACP "response" event (the normal release signal — see
# _DeliveryCoordinator) never showed up in the recorder log (a dropped or
# delayed log line, or Kiro exiting right after answering). Long enough that
# it never fires for the ordinary case (the response event normally shows up
# within one or two poll ticks), short enough that a genuinely lost event
# doesn't wedge every later request behind it for long.
_COORDINATOR_WATCHDOG_S = 15.0


@dataclass(frozen=True)
class KiroPermissionRequest:
    """A parsed Kiro ``session/request_permission`` request."""

    request_id: str
    tool_call_id: str
    title: str
    accept_option_id: str
    decline_option_id: str
    # Kiro's TUI offers a third "Trust, always allow in this session" option
    # alongside the one-time allow/decline pair on (in practice) every
    # permission prompt. Optional rather than required so a future Kiro build
    # that omits it for some prompt kinds degrades to the binary card instead
    # of dropping the whole request (see the accept/decline guard below).
    always_option_id: str | None = None

    @property
    def preview(self) -> str:
        return self.title[:_PREVIEW_MAX]


@dataclass(frozen=True)
class _PermissionEvent:
    """One parsed permission event from Kiro's ACP recorder."""

    kind: str
    request_id: str
    permission: KiroPermissionRequest | None = None


@dataclass(frozen=True)
class _PendingPermission:
    """One Kiro permission currently parked in the web UI."""

    elicitation_id: str
    task: asyncio.Task[None]


class _DeliveryCoordinator:
    """Serializes and orders keystroke delivery to Kiro's single-prompt TUI.

    Kiro can emit many ``session/request_permission`` calls up front (e.g. a
    batch of file edits) but its TUI is strictly modal: only one approval
    prompt is ever visible, always the oldest unanswered one, and Kiro only
    advances once that exact prompt is answered. If concurrent tasks each
    independently polled "is *a* prompt showing and focused on allow" and
    fired Enter, whichever task saw that state first would answer whatever
    prompt happened to be visible — not necessarily its own request. With a
    high volume of concurrent requests this caused tasks to race, some
    requests to never even get parked with the web UI, and the whole batch
    to wedge.

    This coordinator keeps a FIFO queue in the exact order
    ``request_permission`` events were parsed (which matches the order Kiro
    presents them, since Kiro only ever shows the oldest unanswered one) and
    only lets a task touch the tmux pane once it is at the front of that
    queue. A slot is only popped once Kiro's own ACP log confirms — via a
    ``response`` event — that the request was actually resolved, not merely
    when our keystroke-send call returns; that is the only signal that
    reliably means "the visible prompt moved on."
    """

    def __init__(self) -> None:
        self._order: list[str] = []
        self._condition = asyncio.Condition()

    def register(self, request_id: str) -> None:
        self._order.append(request_id)

    async def wait_turn(self, request_id: str) -> None:
        async with self._condition:
            await self._condition.wait_for(
                lambda: bool(self._order) and self._order[0] == request_id
            )

    async def complete(self, request_id: str) -> None:
        async with self._condition:
            with contextlib.suppress(ValueError):
                self._order.remove(request_id)
            self._condition.notify_all()


def kiro_permission_elicitation_id(session_id: str, request_id: str) -> str:
    """Return the deterministic Omnigent elicitation id for a Kiro request."""
    digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:16]
    return f"elicit_kiro_{session_id}_{digest}"


def _consume_task_result(task: asyncio.Task[None]) -> None:
    """Retrieve task exceptions so cancelled loser tasks do not warn."""
    with contextlib.suppress(asyncio.CancelledError):
        task.exception()


# Keeps a strong reference to in-flight watchdogs so the event loop can't
# garbage-collect them mid-sleep (a bare ``asyncio.create_task`` result with
# nothing holding it is only weakly referenced from the loop's perspective).
_watchdog_tasks: set[asyncio.Task[None]] = set()


async def _release_coordinator_slot_after(
    coordinator: _DeliveryCoordinator, request_id: str, delay_s: float
) -> None:
    """Fallback release if Kiro's ACP response event for *request_id* never arrives.

    ``_DeliveryCoordinator.complete`` is idempotent (a missing id is a no-op,
    see its ``suppress(ValueError)``), so this racing with the normal
    response-event release in :func:`supervise_kiro_permission_mirror` is safe
    either order.
    """
    await asyncio.sleep(delay_s)
    await coordinator.complete(request_id)


def _spawn_coordinator_watchdog(coordinator: _DeliveryCoordinator, request_id: str) -> None:
    task = asyncio.create_task(
        _release_coordinator_slot_after(coordinator, request_id, _COORDINATOR_WATCHDOG_S),
        name=f"kiro-permission-watchdog-{request_id}",
    )
    _watchdog_tasks.add(task)
    task.add_done_callback(_watchdog_tasks.discard)


def parse_permission_request(message: dict[str, object]) -> KiroPermissionRequest | None:
    """Parse a Kiro ACP ``session/request_permission`` message."""
    if message.get("method") != "session/request_permission":
        return None
    request_id = message.get("id")
    if not isinstance(request_id, str) or not request_id:
        return None
    params = message.get("params")
    if not isinstance(params, dict):
        return None
    tool_call = params.get("toolCall")
    if not isinstance(tool_call, dict):
        return None
    tool_call_id = tool_call.get("toolCallId")
    if not isinstance(tool_call_id, str) or not tool_call_id:
        return None
    title = tool_call.get("title")
    if not isinstance(title, str) or not title.strip():
        return None
    options = params.get("options")
    if not isinstance(options, list):
        return None
    accept_option_id: str | None = None
    decline_option_id: str | None = None
    always_option_id: str | None = None
    for option in options:
        if not isinstance(option, dict):
            continue
        option_id = option.get("optionId")
        kind = option.get("kind")
        if not isinstance(option_id, str) or not isinstance(kind, str):
            continue
        if kind == _SUPPORTED_ACCEPT_OPTION:
            accept_option_id = option_id
        elif kind == _SUPPORTED_DECLINE_OPTION:
            decline_option_id = option_id
        elif kind == _SUPPORTED_ALWAYS_OPTION:
            always_option_id = option_id
    if not accept_option_id or not decline_option_id:
        return None
    return KiroPermissionRequest(
        request_id=request_id,
        tool_call_id=tool_call_id,
        title=title.strip(),
        accept_option_id=accept_option_id,
        decline_option_id=decline_option_id,
        always_option_id=always_option_id,
    )


def _permission_result_request_id(message: dict[str, object]) -> str | None:
    """Return the request id for a Kiro permission response message."""
    request_id = message.get("id")
    if not isinstance(request_id, str) or not request_id:
        return None
    result = message.get("result")
    if not isinstance(result, dict):
        return None
    outcome = result.get("outcome")
    if not isinstance(outcome, dict):
        return None
    option_id = outcome.get("optionId")
    return request_id if isinstance(option_id, str) and option_id else None


def _decode_acp_message(record: object) -> dict[str, object] | None:
    """Decode the JSON-RPC message from one Kiro recorder line."""
    if not isinstance(record, dict):
        return None
    message = record.get("msg")
    if isinstance(message, str):
        try:
            message = json.loads(message)
        except ValueError:
            return None
    return message if isinstance(message, dict) else None


def _read_new_permission_events(
    record_file: Path, offset: int
) -> tuple[list[_PermissionEvent], int]:
    """Read complete Kiro ACP recorder lines after *offset*."""
    try:
        size = record_file.stat().st_size
    except OSError:
        return [], offset
    if size < offset:
        offset = 0
    if size == offset:
        return [], offset
    try:
        with record_file.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(size - offset)
    except OSError:
        return [], offset
    last_nl = data.rfind(b"\n")
    if last_nl == -1:
        return [], offset
    consumed = data[: last_nl + 1]
    new_offset = offset + len(consumed)
    events: list[_PermissionEvent] = []
    for raw in consumed.split(b"\n"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            record = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        message = _decode_acp_message(record)
        if message is None:
            continue
        permission = parse_permission_request(message)
        if permission is not None:
            events.append(_PermissionEvent("request", permission.request_id, permission))
            continue
        response_id = _permission_result_request_id(message)
        if response_id is not None:
            events.append(_PermissionEvent("response", response_id, None))
    return events, new_offset


async def supervise_kiro_permission_mirror(
    *,
    base_url: str,
    headers: dict[str, str],
    session_id: str,
    bridge_dir: Path,
    auth: httpx.Auth | None = None,
    poll_interval_s: float = _POLL_INTERVAL_S,
) -> None:
    """Tail Kiro's TUI ACP recorder and mirror approvals to web elicitations."""
    record_file = acp_record_path(bridge_dir)
    try:
        offset = record_file.stat().st_size
    except OSError:
        offset = 0
    pending: dict[str, _PendingPermission] = {}
    coordinator = _DeliveryCoordinator()
    timeout = httpx.Timeout(_POST_TIMEOUT_S, connect=10.0)
    from omnigent.cli_auth import open_server_client

    async with open_server_client(base_url, headers=headers, auth=auth, timeout=timeout) as client:
        while True:
            try:
                events, offset = await asyncio.to_thread(
                    _read_new_permission_events, record_file, offset
                )
                # Reap finished delivery tasks so a completed or failed web verdict
                # frees that request's slot. Without this, a keystroke-delivery
                # failure would leave the slot occupied forever and silently block
                # a later response event for the same request from finding its
                # entry. A late matching response event then finds no pending
                # entry and is safely ignored.
                for done_id in [rid for rid, entry in pending.items() if entry.task.done()]:
                    pending.pop(done_id, None)
                resolved_in_batch = {
                    event.request_id for event in events if event.kind == "response"
                }
                for event in events:
                    if event.kind == "request":
                        # Kiro can emit more than one session/request_permission
                        # before the first is answered (e.g. a batch of tool
                        # calls). Track each request_id independently instead of
                        # gating on "any pending" — the previous single-slot
                        # check silently dropped every request after the first,
                        # leaving Kiro's TUI blocked on a prompt the web mirror
                        # never surfaced.
                        if (
                            event.permission is None
                            or event.request_id in resolved_in_batch
                            or event.request_id in pending
                        ):
                            continue
                        elicitation_id = kiro_permission_elicitation_id(
                            session_id, event.request_id
                        )
                        coordinator.register(event.request_id)
                        task = asyncio.create_task(
                            _run_one_permission(
                                client,
                                session_id=session_id,
                                bridge_dir=bridge_dir,
                                permission=event.permission,
                                elicitation_id=elicitation_id,
                                coordinator=coordinator,
                            ),
                            name=f"kiro-permission-{event.request_id}",
                        )
                        task.add_done_callback(_consume_task_result)
                        pending[event.request_id] = _PendingPermission(elicitation_id, task)
                    else:
                        # Kiro's ACP response is the only reliable signal that the
                        # visible prompt actually moved on (our own keystroke-send
                        # call returning isn't enough — see _DeliveryCoordinator).
                        await coordinator.complete(event.request_id)
                        entry = pending.pop(event.request_id, None)
                        if entry is None:
                            continue
                        if not entry.task.done():
                            await _post_external_elicitation_resolved(
                                client, session_id, entry.elicitation_id
                            )
                            entry.task.cancel()
            except asyncio.CancelledError:
                raise
            except Exception:
                _logger.exception(
                    "kiro permission mirror poll failed; session=%s bridge_dir=%s",
                    session_id,
                    bridge_dir,
                )
            await asyncio.sleep(poll_interval_s)


async def _run_one_permission(
    client: httpx.AsyncClient,
    *,
    session_id: str,
    bridge_dir: Path,
    permission: KiroPermissionRequest,
    elicitation_id: str,
    coordinator: _DeliveryCoordinator,
) -> None:
    """Park one Kiro permission request on the server and deliver the verdict.

    Every exit path must free this request's coordinator slot exactly once,
    but *when* it does so matters:

    - Any early return before delivery is attempted (POST failed, non-2xx,
      non-JSON body, no usable action) leaves Kiro's prompt never reached, so
      nothing will ever generate an ACP "response" event for this request —
      the ``finally`` below releases the slot immediately in that case, via
      ``delivered_ok`` staying ``False``.
    - Once ``send_kiro_permission_verdict`` actually returns successfully,
      the slot must instead wait for Kiro's own ACP "response" event (handled
      in the main poll loop) before releasing — that event is the only
      reliable signal the visible prompt actually moved on (see
      ``_DeliveryCoordinator``). Releasing immediately on keystroke-send
      *return* instead of on Kiro's confirmed *response* used to let the next
      queued request touch the pane before Kiro repainted it past the prompt
      we just answered, landing its own delivery on our still-visible prompt
      instead of its own (silently misdirected approvals, no card ever shown
      for the misdirected request). A watchdog (``_spawn_coordinator_watchdog``)
      still releases the slot on a delay as a safety net in case that response
      event is ever dropped — matching the original defense this function's
      unconditional ``finally`` was written for, without paying for it on
      every successful delivery.
    """
    delivered_ok = False
    try:
        payload: dict[str, Any] = {
            "elicitation_id": elicitation_id,
            "agent": "Kiro",
            "policy_name": "kiro_native_permission",
            "operation_type": "tool",
            "message": f"Kiro wants approval for {permission.preview}",
            "content_preview": permission.preview,
            # Untruncated: Kiro's ACP tool_call title is often the full
            # shell command, and the 1024-char content_preview cap
            # (shared by every native-permission producer, see
            # ``_PREVIEW_MAX``) was silently cutting long commands off
            # in the approval dialog before a human ever saw the rest.
            # The web UI renders this separately, in a scrollable block
            # that isn't subject to that cap (see ApprovalCard's
            # ``kiroCommand`` branch) — same technique
            # ``_codex_command_approval_params`` uses for Codex.
            "command": permission.title,
        }
        # Tells the server this prompt also has Kiro's "Trust, always allow
        # in this session" option, so the web card can grow the third
        # button (see ApprovalCard's ``kiroTrustAlways`` prop). Omitted
        # (rather than sent as false) when Kiro didn't offer that option on
        # this particular prompt.
        if permission.always_option_id:
            payload["kiro_trust_always"] = True
        response = await _post_hook_with_retry(client, session_id=session_id, payload=payload)
        if response is None:
            # Retries exhausted — the elicitation card was never created, so
            # Kiro's TUI is now waiting on a decision the web UI never got a
            # chance to surface. Without this notice the turn just looks like
            # it is still thinking; say so explicitly instead.
            await _post_external_assistant_notice(
                client,
                session_id=session_id,
                text=(
                    "⚠️ Kiro está esperando aprovação para "
                    f"`{permission.preview}`, mas o Omnigent não conseguiu registrar "
                    "essa aprovação no servidor após 3 tentativas. A sessão pode "
                    "estar parada esperando uma decisão manual no terminal."
                ),
            )
            return
        if response.status_code >= 400:
            _logger.warning(
                "kiro permission hook rejected: status=%s body=%s",
                response.status_code,
                response.text[:512],
            )
            await _post_external_assistant_notice(
                client,
                session_id=session_id,
                text=(
                    "⚠️ Kiro está esperando aprovação para "
                    f"`{permission.preview}`, mas o servidor rejeitou o pedido "
                    f"(HTTP {response.status_code}). A sessão pode estar parada "
                    "esperando uma decisão manual no terminal."
                ),
            )
            return
        if not response.content:
            return
        try:
            result = response.json()
        except ValueError:
            _logger.warning("kiro permission hook returned non-JSON: %s", response.text[:512])
            return
        action = result.get("action") if isinstance(result, dict) else None
        if action not in {"accept", "decline", "cancel"}:
            return
        # The wire ``action`` is always accept/decline/cancel (MCP's
        # ElicitResult shape — see ElicitationResult in server/schemas.py);
        # "trust always" rides as a content flag on an accepted verdict,
        # mirroring how Claude-native's "remember"/"allow_all_edits" extras
        # work. Only honored when THIS prompt actually offered Kiro's
        # "Trust, always allow" option — a stray flag on an ineligible
        # prompt (e.g. one Kiro didn't offer it for) falls back to a normal
        # one-time accept rather than erroring.
        content = result.get("content") if isinstance(result, dict) else None
        deliver_action = action
        if (
            action == "accept"
            and permission.always_option_id
            and isinstance(content, dict)
            and content.get("kiro_trust_always") is True
        ):
            deliver_action = "allow_always"
        # Wait until this is the oldest still-unanswered request before
        # touching the shared tmux pane — Kiro only ever shows one prompt at
        # a time, and it's always this one's turn only once every older
        # request has been confirmed resolved (see _DeliveryCoordinator).
        await coordinator.wait_turn(permission.request_id)
        try:
            await asyncio.to_thread(
                send_kiro_permission_verdict,
                bridge_dir,
                action=deliver_action,
                has_trust_always_option=permission.always_option_id is not None,
            )
            delivered_ok = True
        except RuntimeError:
            _logger.exception(
                "failed to deliver kiro permission verdict for %s; session=%s",
                permission.request_id,
                session_id,
            )
            # The web UI already showed the approval and recorded a verdict —
            # from the user's side this looked handled. Say plainly that the
            # keystroke never reached the TUI, so "approved but nothing
            # happened" doesn't read as ongoing processing.
            await _post_external_assistant_notice(
                client,
                session_id=session_id,
                text=(
                    "⚠️ A aprovação para "
                    f"`{permission.preview}` foi registrada, mas o Omnigent não "
                    "conseguiu confirmar que o Kiro recebeu a decisão no terminal. "
                    "Verifique a sessão — pode ser necessário aprovar manualmente."
                ),
            )
    finally:
        if delivered_ok:
            # Kiro's own ACP "response" event is the real release signal
            # (see _DeliveryCoordinator and the docstring above) — the
            # watchdog is only a fallback in case that event is dropped.
            _spawn_coordinator_watchdog(coordinator, permission.request_id)
        else:
            await coordinator.complete(permission.request_id)


async def _post_hook_with_retry(
    client: httpx.AsyncClient, *, session_id: str, payload: dict[str, Any]
) -> httpx.Response | None:
    """POST the native-permission-request hook, retrying transient failures.

    Retries a connection error or 5xx response (proxy/server hiccups, like
    the single 502 that motivated this) up to :data:`_HOOK_POST_MAX_ATTEMPTS`
    times with short backoff. A 4xx is not retried — that is a request the
    server actively rejected, not a blip, and won't succeed on replay.
    Returns ``None`` only once every attempt has failed to produce a usable
    response, so the caller can tell "never even asked the server" apart
    from "server answered but declined."
    """
    last_response: httpx.Response | None = None
    for attempt in range(_HOOK_POST_MAX_ATTEMPTS):
        try:
            response = await client.post(
                f"/v1/sessions/{session_id}/hooks/native-permission-request",
                json=payload,
            )
        except httpx.HTTPError:
            _logger.warning(
                "kiro permission hook POST failed (attempt %d/%d); session=%s",
                attempt + 1,
                _HOOK_POST_MAX_ATTEMPTS,
                session_id,
                exc_info=True,
            )
        else:
            if response.status_code < 500:
                return response
            last_response = response
            _logger.warning(
                "kiro permission hook returned %s (attempt %d/%d); session=%s",
                response.status_code,
                attempt + 1,
                _HOOK_POST_MAX_ATTEMPTS,
                session_id,
            )
        if attempt < len(_HOOK_POST_RETRY_DELAYS_S):
            await asyncio.sleep(_HOOK_POST_RETRY_DELAYS_S[attempt])
    return last_response


async def _post_external_assistant_notice(
    client: httpx.AsyncClient, *, session_id: str, text: str
) -> None:
    """Post a visible system notice into the conversation timeline.

    Uses the ``external_assistant_message`` event type, which persists and
    broadcasts append-only conversation history without touching Omnigent's
    task/turn state (server-side: ``_persist_external_assistant_message`` —
    "bypasses the legacy persist path so mirroring a terminal response does
    not create or steer an Omnigent agent task"). That property matters here:
    a failed hook POST or verdict delivery happens outside any turn Omnigent
    is tracking, so this must not look like the agent said something or be
    mistaken for a real turn completing — it is purely an out-of-band notice
    so a stalled approval reads as "something failed," not as ordinary
    "still thinking" silence.
    """
    try:
        response = await client.post(
            f"/v1/sessions/{session_id}/events",
            json={
                "type": "external_assistant_message",
                "data": {"agent": "Kiro", "text": text},
            },
            timeout=10.0,
        )
        if response.status_code >= 400:
            _logger.warning(
                "kiro external_assistant_message rejected: status=%s body=%s",
                response.status_code,
                response.text[:512],
            )
    except httpx.HTTPError:
        _logger.exception("kiro external_assistant_message POST failed")


async def _post_external_elicitation_resolved(
    client: httpx.AsyncClient, session_id: str, elicitation_id: str
) -> None:
    """Tell the server the native Kiro TUI answered a pending prompt."""
    try:
        response = await client.post(
            f"/v1/sessions/{session_id}/events",
            json={
                "type": "external_elicitation_resolved",
                "data": {"elicitation_id": elicitation_id},
            },
            timeout=10.0,
        )
        if response.status_code >= 400:
            _logger.warning(
                "kiro external_elicitation_resolved rejected: status=%s body=%s",
                response.status_code,
                response.text[:512],
            )
    except httpx.HTTPError:
        _logger.exception("kiro external_elicitation_resolved POST failed")


__all__ = [
    "KiroPermissionRequest",
    "kiro_permission_elicitation_id",
    "parse_permission_request",
    "supervise_kiro_permission_mirror",
]
