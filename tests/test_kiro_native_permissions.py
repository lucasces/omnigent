"""Tests for the Kiro-native ACP permission mirror."""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
from pathlib import Path

import httpx
import pytest

from omnigent import kiro_native_permissions as knp
from omnigent.kiro_native_bridge import acp_record_path
from omnigent.kiro_native_permissions import (
    kiro_permission_elicitation_id,
    parse_permission_request,
)


def _permission_msg(
    request_id: str = "req-1",
    *,
    allow_option_id: str = "allow_once",
    reject_option_id: str = "reject_once",
) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "session/request_permission",
        "params": {
            "sessionId": "kiro-session",
            "toolCall": {"toolCallId": f"tool-{request_id}", "title": "Running: pwd"},
            "options": [
                {"optionId": allow_option_id, "name": "Yes", "kind": "allow_once"},
                {"optionId": "allow_always", "name": "Always", "kind": "allow_always"},
                {"optionId": reject_option_id, "name": "No", "kind": "reject_once"},
            ],
            "_meta": {"trustOptions": True},
        },
    }


def _permission_result_msg(request_id: str = "req-1", option_id: str = "allow_once") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"outcome": {"outcome": "selected", "optionId": option_id}},
    }


def _permission_cancelled_msg(request_id: str = "req-1") -> dict:
    """A prompt resolved by cancellation (turn interrupted / declined-via-interrupt).

    Kiro reports this as ``{"outcome":"cancelled"}`` with no ``optionId`` —
    distinct from a user selection, but still a terminal response.
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"outcome": {"outcome": "cancelled"}},
    }


def _record(message: dict, *, direction: str = "out") -> dict:
    return {"ts": "2026-06-25T00:00:00Z", "dir": direction, "msg": json.dumps(message)}


def _record_bytes(message: dict, *, direction: str = "out") -> bytes:
    return (json.dumps(_record(message, direction=direction)) + "\n").encode("utf-8")


def test_parse_permission_request_extracts_one_time_options() -> None:
    req = parse_permission_request(_permission_msg())

    assert req is not None
    assert req.request_id == "req-1"
    assert req.tool_call_id == "tool-req-1"
    assert req.title == "Running: pwd"
    assert req.accept_option_id == "allow_once"
    assert req.decline_option_id == "reject_once"
    assert req.always_option_id == "allow_always"
    assert req.preview == "Running: pwd"


def test_parse_permission_request_preserves_option_ids_by_kind() -> None:
    req = parse_permission_request(
        _permission_msg("req-1", allow_option_id="yes-1", reject_option_id="no-1")
    )

    assert req is not None
    assert req.accept_option_id == "yes-1"
    assert req.decline_option_id == "no-1"


def test_parse_permission_request_leaves_always_option_none_when_absent() -> None:
    msg = _permission_msg("req-1")
    msg["params"]["options"] = [
        opt for opt in msg["params"]["options"] if opt["kind"] != "allow_always"
    ]

    req = parse_permission_request(msg)

    assert req is not None
    assert req.always_option_id is None


def test_parse_permission_request_extracts_full_command_from_trust_options() -> None:
    msg = _permission_msg("req-1")
    msg["params"]["toolCall"]["title"] = "Running: bash -lc '...truncated by kiro..."
    msg["params"]["_meta"] = {
        "trustOptions": [
            {
                "label": "Full command",
                "display": "bash -lc 'echo one\necho two\necho THIS_IS_THE_FULL_COMMAND'",
                "setting_key": "allowedCommands",
                "patterns": ["bash( .*)?"],
            },
            {"label": "Base command", "display": "bash *", "setting_key": "allowedCommands"},
        ]
    }

    req = parse_permission_request(msg)

    assert req is not None
    assert req.full_command == "bash -lc 'echo one\necho two\necho THIS_IS_THE_FULL_COMMAND'"
    # Kiro's own trust submenu can't afford to truncate the command it
    # builds an allow-pattern from, so the untruncated row wins over the
    # (possibly cut) title in both the payload command and the preview.
    assert req.preview == req.full_command


def test_parse_permission_request_falls_back_to_title_without_full_command_row() -> None:
    msg = _permission_msg("req-1")
    msg["params"]["_meta"] = {"trustOptions": [{"label": "Base command", "display": "bash *"}]}

    req = parse_permission_request(msg)

    assert req is not None
    assert req.full_command is None
    assert req.preview == req.title


def test_parse_permission_request_uses_raw_input_command_when_meta_is_absent() -> None:
    """A ``shell`` tool call invoked outside Kiro's native trust flow (e.g. a
    Bedrock/Claude-invoked agent) ships no ``_meta`` at all, so
    ``_extract_full_command`` can't help — mirrors the real ACP request
    captured in production, where ``params`` was just
    ``{sessionId, toolCall: {toolCallId, title, rawInput}, options}``. The
    untruncated command must come from ``toolCall.rawInput.command`` instead.
    """
    msg = _permission_msg("req-1")
    del msg["params"]["_meta"]
    msg["params"]["toolCall"]["title"] = "Running: bash -lc '...truncated by kiro...'"
    msg["params"]["toolCall"]["rawInput"] = {
        "command": "bash -lc 'echo one\necho two\necho THIS_IS_THE_FULL_COMMAND'"
    }

    req = parse_permission_request(msg)

    assert req is not None
    assert req.full_command == "bash -lc 'echo one\necho two\necho THIS_IS_THE_FULL_COMMAND'"
    assert req.preview == req.full_command


def test_parse_permission_request_prefers_trust_options_over_raw_input_command() -> None:
    msg = _permission_msg("req-1")
    msg["params"]["_meta"] = {
        "trustOptions": [{"label": "Full command", "display": "from-trust-options"}]
    }
    msg["params"]["toolCall"]["rawInput"] = {"command": "from-raw-input"}

    req = parse_permission_request(msg)

    assert req is not None
    assert req.full_command == "from-trust-options"


def test_parse_permission_request_ignores_raw_input_without_command_field() -> None:
    """``rawInput`` on non-shell tool calls (e.g. a file edit) has no
    ``command`` key — the raw-input fallback must not misfire for those and
    should leave ``full_command`` unset so callers still fall back to
    ``title``.
    """
    msg = _permission_msg("req-1")
    del msg["params"]["_meta"]
    msg["params"]["toolCall"]["rawInput"] = {"path": "/tmp/foo.txt", "content": "..."}

    req = parse_permission_request(msg)

    assert req is not None
    assert req.full_command is None
    assert req.preview == req.title


def test_parse_permission_request_captures_subagent_session_id() -> None:
    req = parse_permission_request(_permission_msg("req-1"))

    assert req is not None
    assert req.subagent_session_id == "kiro-session"


def test_parse_permission_request_leaves_subagent_session_id_none_when_absent() -> None:
    msg = _permission_msg("req-1")
    del msg["params"]["sessionId"]

    req = parse_permission_request(msg)

    assert req is not None
    assert req.subagent_session_id is None


def test_parse_subagent_session_names_maps_session_id_to_name() -> None:
    message = {
        "jsonrpc": "2.0",
        "method": "_kiro.dev/subagent/list_update",
        "params": {
            "subagents": [
                {"sessionId": "sess-1", "sessionName": "sleep1"},
                {"sessionId": "sess-2", "sessionName": "sleep2"},
                {"sessionId": "", "sessionName": "no-id"},
                {"sessionId": "sess-3"},
                "not-a-dict",
            ],
            "pendingStages": [],
        },
    }

    names = knp._parse_subagent_session_names(message)

    assert names == {"sess-1": "sleep1", "sess-2": "sleep2"}


def test_parse_subagent_session_names_ignores_other_methods() -> None:
    assert knp._parse_subagent_session_names({"method": "session/prompt", "params": {}}) == {}


@pytest.mark.parametrize(
    "message",
    [
        pytest.param({"method": "session/prompt"}, id="not-permission"),
        pytest.param({**_permission_msg(), "id": ""}, id="missing-id"),
        pytest.param(
            {
                **_permission_msg(),
                "params": {**_permission_msg()["params"], "toolCall": {"title": "Running: pwd"}},
            },
            id="missing-tool-call-id",
        ),
        pytest.param(
            {
                **_permission_msg(),
                "params": {
                    **_permission_msg()["params"],
                    "toolCall": {"toolCallId": "tool-1"},
                },
            },
            id="missing-title",
        ),
        pytest.param(
            {**_permission_msg(), "params": {**_permission_msg()["params"], "options": []}},
            id="missing-one-time-options",
        ),
    ],
)
def test_parse_permission_request_returns_none_for_unsupported_shapes(message: dict) -> None:
    assert parse_permission_request(message) is None


def test_permission_result_request_id_extraction() -> None:
    assert knp._permission_result_request_id(_permission_result_msg("req-9")) == "req-9"
    # A cancelled prompt has no optionId but is still a terminal response that
    # must free the request's coordinator slot — see the leak it otherwise
    # caused in _permission_result_request_id's comment.
    assert knp._permission_result_request_id(_permission_cancelled_msg("req-9")) == "req-9"
    assert knp._permission_result_request_id({"id": "req-9", "result": {}}) is None
    # An empty outcome dict is neither a selection nor a cancellation.
    assert knp._permission_result_request_id({"id": 1, "result": {"outcome": {}}}) is None
    assert (
        knp._permission_result_request_id(
            {"id": "req-9", "result": {"outcome": {"outcome": "selected"}}}
        )
        is None
    )


def test_read_new_permission_events_recognizes_cancelled_response(tmp_path: Path) -> None:
    """A cancelled outcome is parsed as a 'response' event, not silently dropped.

    Regression guard for the coordinator-slot leak: keying the response parse
    on ``optionId`` alone dropped the cancelled shape, so the mirror never
    released the request's slot on a decline-via-interrupt.
    """
    record_file = tmp_path / "kiro_acp_record.jsonl"
    record_file.write_bytes(
        _record_bytes(_permission_msg("req-1")) + _record_bytes(_permission_cancelled_msg("req-1"))
    )

    events, _names, _offset = knp._read_new_permission_events(record_file, 0)

    assert [(event.kind, event.request_id) for event in events] == [
        ("request", "req-1"),
        ("response", "req-1"),
    ]


def test_elicitation_id_is_deterministic_and_session_scoped() -> None:
    eid = kiro_permission_elicitation_id("conv_abc", "req-1")
    assert eid == kiro_permission_elicitation_id("conv_abc", "req-1")
    assert eid != kiro_permission_elicitation_id("conv_other", "req-1")
    assert eid.startswith("elicit_kiro_conv_abc_")


def test_read_new_permission_events_incremental_and_partial_line(tmp_path: Path) -> None:
    record_file = tmp_path / "kiro_acp_record.jsonl"
    record_file.write_bytes(_record_bytes(_permission_msg("req-1")))

    events, _names, offset = knp._read_new_permission_events(record_file, 0)

    assert [(event.kind, event.request_id) for event in events] == [("request", "req-1")]

    with record_file.open("ab") as handle:
        handle.write(_record_bytes(_permission_result_msg("req-1"), direction="in"))
        handle.write(b'{"dir":"out","msg":"')

    events2, _names2, offset2 = knp._read_new_permission_events(record_file, offset)

    assert [(event.kind, event.request_id) for event in events2] == [("response", "req-1")]
    assert offset2 == offset + len(_record_bytes(_permission_result_msg("req-1"), direction="in"))


def test_read_new_permission_events_collects_subagent_name_updates(tmp_path: Path) -> None:
    record_file = tmp_path / "kiro_acp_record.jsonl"
    first_snapshot = {
        "jsonrpc": "2.0",
        "method": "_kiro.dev/subagent/list_update",
        "params": {"subagents": [{"sessionId": "sess-1", "sessionName": "sleep1"}]},
    }
    second_snapshot = {
        "jsonrpc": "2.0",
        "method": "_kiro.dev/subagent/list_update",
        "params": {
            "subagents": [
                {"sessionId": "sess-1", "sessionName": "sleep1"},
                {"sessionId": "sess-2", "sessionName": "sleep2"},
            ]
        },
    }
    record_file.write_bytes(_record_bytes(first_snapshot) + _record_bytes(second_snapshot))

    events, names, _offset = knp._read_new_permission_events(record_file, 0)

    assert events == []
    assert names == {"sess-1": "sleep1", "sess-2": "sleep2"}


def test_read_new_permission_events_ignores_malformed_and_non_permission(tmp_path: Path) -> None:
    record_file = tmp_path / "kiro_acp_record.jsonl"
    record_file.write_bytes(
        b"not-json\n"
        + _record_bytes({"jsonrpc": "2.0", "method": "session/prompt"})
        + _record_bytes(_permission_msg("req-1"))
    )

    events, _names, _offset = knp._read_new_permission_events(record_file, 0)

    assert [(event.kind, event.request_id) for event in events] == [("request", "req-1")]


class _QueueClient:
    """Async httpx-client stub: records POSTs, returns queued responses."""

    def __init__(self, responses: list[httpx.Response]) -> None:
        self.posts: list[tuple[str, dict]] = []
        self._responses = list(responses)

    async def post(self, url: str, *, json: dict, **_kw: object) -> httpx.Response:
        self.posts.append((url, json))
        return self._responses.pop(0)


@pytest.mark.parametrize(
    ("response", "expected_action"),
    [
        pytest.param(httpx.Response(200, json={"action": "accept"}), "accept", id="accept"),
        # A classic-prompt decline delivers NOTHING via keystroke — the
        # server-side interrupt (Escape) already refused the tool. Typing "No"
        # on top would latch onto the next command's prompt (see the decline
        # branch in _run_one_permission).
        pytest.param(
            httpx.Response(200, json={"action": "decline"}), "decline-noop", id="decline"
        ),
        pytest.param(httpx.Response(200, json={"action": "cancel"}), "cancel", id="cancel"),
        pytest.param(
            httpx.Response(200, json={"action": "accept", "content": {"kiro_trust_always": True}}),
            "allow_always",
            id="accept-trust-always",
        ),
        pytest.param(httpx.Response(200), None, id="empty-200"),
        pytest.param(httpx.Response(400, text="nope"), None, id="rejected"),
        pytest.param(httpx.Response(200, content=b"not-json"), None, id="non-json"),
    ],
)
@pytest.mark.asyncio
async def test_run_one_permission_posts_then_delivers_verdict(
    response: httpx.Response,
    expected_action: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delivered: list[tuple[Path, str]] = []
    trust_scope_navigations: list[Path] = []

    def _fake_send(bridge_dir: Path, *, action: str, **_kw: object) -> None:
        delivered.append((bridge_dir, action))

    def _fake_navigate(bridge_dir: Path, **_kw: object) -> list[str]:
        # No submenu offered for this prompt kind — the "Trust, always
        # allow" verdict resolves directly. The submenu-present path is
        # covered by test_deliver_allow_always_resolves_trust_scope_pick.
        trust_scope_navigations.append(bridge_dir)
        return []

    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _fake_send)
    monkeypatch.setattr(knp, "navigate_to_kiro_trust_scope", _fake_navigate)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    # A second queued response absorbs the "hook rejected" assistant-notice
    # POST the >=400 branch fires — unused by every other parametrized case,
    # which returns before that second POST would happen.
    client = _QueueClient([response, httpx.Response(200)])
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={},
    )

    url, body = client.posts[0]
    assert url == "/v1/sessions/conv_1/hooks/native-permission-request"
    assert body == {
        "elicitation_id": "elic_1",
        "agent": "Kiro",
        "policy_name": "kiro_native_permission",
        "operation_type": "tool",
        "message": "Kiro wants approval for Running: pwd",
        "content_preview": "Running: pwd",
        "command": "Running: pwd",
        # _permission_msg() always offers Kiro's "allow_always" option.
        "kiro_trust_always": True,
        # A classic (non-subagent) prompt advertises native reject-with-feedback.
        "kiro_reject_with_feedback": True,
    }
    if expected_action in (None, "decline-noop"):
        # None: the POST returned no usable action, so nothing is delivered.
        # decline-noop: a classic decline intentionally delivers no keystroke
        # (the interrupt already refused the tool) — the guard against the
        # zombie-thread misfire.
        assert delivered == []
        assert trust_scope_navigations == []
    elif expected_action == "allow_always":
        # allow_always routes through navigate_to_kiro_trust_scope instead
        # of send_kiro_permission_verdict — see _deliver_allow_always.
        assert delivered == []
        assert trust_scope_navigations == [tmp_path]
    else:
        assert delivered == [(tmp_path, expected_action)]
        assert trust_scope_navigations == []


@pytest.mark.parametrize(
    ("action", "expects_notice"),
    [
        # A failed *approval* means an action the user OK'd never reached the
        # TUI — the notice must fire so the stall is visible.
        pytest.param("accept", True, id="accept-notices"),
        # A failed decline is benign: the server-side interrupt (Escape ->
        # session/cancel) already refused the tool, so the keystroke failing is
        # the expected race, not a stuck session. No false "aprovação
        # registrada" notice.
        pytest.param("decline", False, id="decline-silent"),
        pytest.param("cancel", False, id="cancel-silent"),
    ],
)
@pytest.mark.asyncio
async def test_run_one_permission_delivery_failure_notice_only_for_approvals(
    action: str,
    expects_notice: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_send(bridge_dir: Path, *, action: str, **_kw: object) -> None:
        raise RuntimeError("kiro-native prompt was not focused before delivery")

    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _raise_send)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    # [verdict, (notice)] — the notice POST is only consumed when it fires.
    client = _QueueClient([httpx.Response(200, json={"action": action}), httpx.Response(200)])
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={},
    )

    notice_posts = [
        body
        for url, body in client.posts
        if url == "/v1/sessions/conv_1/events" and body.get("type") == "external_assistant_message"
    ]
    if expects_notice:
        assert len(notice_posts) == 1
        assert "não" in notice_posts[0]["data"]["text"]
    else:
        assert notice_posts == []


@pytest.mark.asyncio
async def test_resolve_kiro_trust_scope_index_matches_chosen_row() -> None:
    """The trust-scope card's answer maps back to the matching row index."""
    rows = ["Full command   sleep 5", "Partial command   sleep 5 *", "Base command   sleep *"]
    client = _QueueClient(
        [httpx.Response(200, json={"action": "accept", "content": {"answer": rows[1]}})]
    )
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None

    index = await knp._resolve_kiro_trust_scope_index(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        permission=req,
        elicitation_id="elic_1",
        rows=rows,
    )

    assert index == 1
    url, body = client.posts[0]
    assert url == "/v1/sessions/conv_1/hooks/native-permission-request"
    assert body["elicitation_id"] == "elic_1_scope"
    assert body["options"] == rows


@pytest.mark.asyncio
async def test_resolve_kiro_trust_scope_index_none_on_unmatched_answer() -> None:
    """An answer matching no row (e.g. Kiro's submenu changed shape) resolves to None."""
    client = _QueueClient(
        [httpx.Response(200, json={"action": "accept", "content": {"answer": "not a row"}})]
    )
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None

    index = await knp._resolve_kiro_trust_scope_index(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        permission=req,
        elicitation_id="elic_1",
        rows=["Full command   pwd", "Entire tool"],
    )

    assert index is None


@pytest.mark.asyncio
async def test_deliver_allow_always_resolves_trust_scope_pick(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When Kiro opens a trust-scope submenu, the human's pick finishes it.

    Covers the branch test_run_one_permission_posts_then_delivers_verdict's
    [accept-trust-always] case deliberately skips (there, navigate returns no
    rows at all).
    """
    rows = ["Full command   sleep 5", "Entire tool"]
    navigate_calls: list[Path] = []
    finish_calls: list[tuple[Path, int]] = []

    def _fake_navigate(bridge_dir: Path, **_kw: object) -> list[str]:
        navigate_calls.append(bridge_dir)
        return rows

    def _fake_finish(bridge_dir: Path, *, option_index: int, **_kw: object) -> None:
        finish_calls.append((bridge_dir, option_index))

    monkeypatch.setattr(knp, "navigate_to_kiro_trust_scope", _fake_navigate)
    monkeypatch.setattr(knp, "send_kiro_trust_scope_verdict", _fake_finish)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    client = _QueueClient(
        [httpx.Response(200, json={"action": "accept", "content": {"answer": rows[1]}})]
    )

    await knp._deliver_allow_always(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
    )

    assert navigate_calls == [tmp_path]
    assert finish_calls == [(tmp_path, 1)]


@pytest.mark.asyncio
async def test_deliver_allow_always_raises_when_pick_unresolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unresolved trust-scope pick (bad hook POST, mismatched answer) surfaces as an error.

    Regression guard: silently leaving the TUI's submenu open with no error
    would look identical to the "still thinking" state the bridge's other
    failure paths are careful to avoid (see _run_one_permission's
    RuntimeError handling).
    """

    def _fake_navigate(bridge_dir: Path, **_kw: object) -> list[str]:
        del bridge_dir
        return ["Full command   pwd"]

    monkeypatch.setattr(knp, "navigate_to_kiro_trust_scope", _fake_navigate)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    client = _QueueClient([httpx.Response(400, text="nope"), httpx.Response(200)])

    with pytest.raises(RuntimeError, match="trust-scope pick"):
        await knp._deliver_allow_always(
            client,  # type: ignore[arg-type]
            session_id="conv_1",
            bridge_dir=tmp_path,
            permission=req,
            elicitation_id="elic_1",
        )


@pytest.mark.asyncio
async def test_deliver_subagent_allow_always_resolves_trust_scope_pick(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subagent counterpart of test_deliver_allow_always_resolves_trust_scope_pick."""
    rows = ["Full command   sleep 5", "Entire tool"]
    navigate_calls: list[tuple[Path, str]] = []
    finish_calls: list[tuple[Path, int]] = []

    def _fake_navigate(bridge_dir: Path, *, subagent_name: str, **_kw: object) -> list[str]:
        navigate_calls.append((bridge_dir, subagent_name))
        return rows

    def _fake_finish(bridge_dir: Path, *, option_index: int, **_kw: object) -> None:
        finish_calls.append((bridge_dir, option_index))

    monkeypatch.setattr(knp, "navigate_to_kiro_subagent_trust_scope", _fake_navigate)
    monkeypatch.setattr(knp, "send_kiro_trust_scope_verdict", _fake_finish)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    client = _QueueClient(
        [httpx.Response(200, json={"action": "accept", "content": {"answer": rows[1]}})]
    )

    await knp._deliver_subagent_allow_always(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        subagent_name="sleep1",
    )

    assert navigate_calls == [(tmp_path, "sleep1")]
    assert finish_calls == [(tmp_path, 1)]


@pytest.mark.asyncio
async def test_run_one_permission_routes_to_subagent_delivery_when_name_known(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sessionId that matches an announced subagent must use the AGENT MONITOR path.

    Regression guard for the actual production bug: routing a subagent's
    request through the classic single-prompt delivery
    (send_kiro_permission_verdict) sends keystrokes at a prompt Kiro isn't
    even showing (Kiro V3 batches these behind the picker instead — see
    send_kiro_subagent_permission_verdict's docstring), so delivery always
    times out.
    """
    subagent_delivered: list[tuple[Path, str, str]] = []
    classic_delivered: list[tuple[Path, str]] = []

    def _fake_subagent_send(
        bridge_dir: Path, *, subagent_name: str, action: str, **_kw: object
    ) -> None:
        subagent_delivered.append((bridge_dir, subagent_name, action))

    def _fake_classic_send(bridge_dir: Path, *, action: str, **_kw: object) -> None:
        classic_delivered.append((bridge_dir, action))

    monkeypatch.setattr(knp, "send_kiro_subagent_permission_verdict", _fake_subagent_send)
    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _fake_classic_send)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    assert req.subagent_session_id == "kiro-session"
    client = _QueueClient([httpx.Response(200, json={"action": "accept"})])
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={"kiro-session": "sleep1"},
    )

    assert subagent_delivered == [(tmp_path, "sleep1", "accept")]
    assert classic_delivered == []


@pytest.mark.asyncio
async def test_run_one_permission_routes_decline_with_feedback_to_native_editor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A classic decline carrying feedback drives Kiro's "Modify request" editor.

    The web card's "Reject with feedback" flow returns
    ``action: "decline"`` with ``content.feedback``; the mirror must route it
    to ``send_kiro_permission_reject_with_feedback`` (Tab-to-edit path) rather
    than the plain-decline no-op — the latter relies on the server interrupt,
    which the server deliberately skips when feedback is present.
    """
    feedback_delivered: list[tuple[Path, str, bool]] = []
    plain_declined: list[tuple[Path, str]] = []

    def _fake_reject_with_feedback(
        bridge_dir: Path, *, feedback: str, has_trust_always_option: bool, **_kw: object
    ) -> None:
        feedback_delivered.append((bridge_dir, feedback, has_trust_always_option))

    def _fake_send(bridge_dir: Path, *, action: str, **_kw: object) -> None:
        plain_declined.append((bridge_dir, action))

    monkeypatch.setattr(
        knp, "send_kiro_permission_reject_with_feedback", _fake_reject_with_feedback
    )
    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _fake_send)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    client = _QueueClient(
        [httpx.Response(200, json={"action": "decline", "content": {"feedback": "use printf"}})]
    )
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={},
    )

    assert feedback_delivered == [(tmp_path, "use printf", True)]
    assert plain_declined == []


@pytest.mark.asyncio
async def test_run_one_permission_blank_feedback_decline_is_plain_noop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whitespace-only feedback is not real feedback — fall back to plain decline.

    A blank ``content.feedback`` must NOT open the "Modify request" editor
    (there's nothing to steer with), and must NOT type "No" either — the
    server interrupt already refused the tool (see the classic-decline no-op
    branch in ``_run_one_permission``).
    """
    feedback_delivered: list[object] = []
    plain_declined: list[object] = []

    def _fake_reject_with_feedback(bridge_dir: Path, **_kw: object) -> None:
        feedback_delivered.append(bridge_dir)

    def _fake_send(bridge_dir: Path, *, action: str, **_kw: object) -> None:
        plain_declined.append((bridge_dir, action))

    monkeypatch.setattr(
        knp, "send_kiro_permission_reject_with_feedback", _fake_reject_with_feedback
    )
    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _fake_send)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    client = _QueueClient(
        [httpx.Response(200, json={"action": "decline", "content": {"feedback": "   "}})]
    )
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={},
    )

    assert feedback_delivered == []
    assert plain_declined == []


@pytest.mark.asyncio
async def test_run_one_permission_routes_allow_always_to_subagent_delivery_when_name_known(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subagent_allow_always: list[Path] = []

    async def _fake_deliver_subagent_allow_always(_client: object, **kwargs: object) -> None:
        subagent_allow_always.append(kwargs["bridge_dir"])  # type: ignore[index]

    async def _fake_deliver_allow_always(_client: object, **_kw: object) -> None:
        raise AssertionError("classic _deliver_allow_always should not run for a subagent request")

    monkeypatch.setattr(knp, "_deliver_subagent_allow_always", _fake_deliver_subagent_allow_always)
    monkeypatch.setattr(knp, "_deliver_allow_always", _fake_deliver_allow_always)
    req = parse_permission_request(_permission_msg("req-1"))
    assert req is not None
    client = _QueueClient(
        [httpx.Response(200, json={"action": "accept", "content": {"kiro_trust_always": True}})]
    )
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={"kiro-session": "sleep1"},
    )

    assert subagent_allow_always == [tmp_path]


@pytest.mark.asyncio
async def test_run_one_permission_omits_trust_always_hint_when_not_offered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delivered_kwargs: dict[str, object] = {}

    def _fake_send(bridge_dir: Path, *, action: str, **kwargs: object) -> None:
        delivered_kwargs.update(kwargs)

    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _fake_send)
    msg = _permission_msg("req-1")
    msg["params"]["options"] = [
        opt for opt in msg["params"]["options"] if opt["kind"] != "allow_always"
    ]
    req = parse_permission_request(msg)
    assert req is not None
    client = _QueueClient([httpx.Response(200, json={"action": "accept"})])
    coordinator = knp._DeliveryCoordinator()
    coordinator.register("req-1")

    await knp._run_one_permission(
        client,  # type: ignore[arg-type]
        session_id="conv_1",
        bridge_dir=tmp_path,
        permission=req,
        elicitation_id="elic_1",
        coordinator=coordinator,
        subagent_names={},
    )

    _url, body = client.posts[0]
    assert "kiro_trust_always" not in body
    # A prompt that never offered "Trust, always allow" is a 2-row menu, so
    # decline/cancel delivery must send one Down instead of two — see
    # send_kiro_permission_verdict's has_trust_always_option.
    assert delivered_kwargs.get("has_trust_always_option") is False


@pytest.mark.asyncio
async def test_post_external_elicitation_resolved_shape() -> None:
    client = _QueueClient([httpx.Response(200)])
    await knp._post_external_elicitation_resolved(client, "conv_2", "elic_9")  # type: ignore[arg-type]
    assert client.posts == [
        (
            "/v1/sessions/conv_2/events",
            {"type": "external_elicitation_resolved", "data": {"elicitation_id": "elic_9"}},
        )
    ]


@pytest.mark.asyncio
async def test_supervise_mirror_parks_then_releases_on_permission_response(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    created: list[object] = []

    class _FakeAsyncClient:
        def __init__(self, **_kw: object) -> None:
            self.posts: list[tuple[str, dict]] = []
            created.append(self)

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, url: str, *, json: dict, **_kw: object) -> httpx.Response:
            self.posts.append((url, json))
            return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(knp.httpx, "AsyncClient", _FakeAsyncClient)

    started = asyncio.Event()
    release = asyncio.Event()
    cancelled = asyncio.Event()

    async def _fake_run_one(_client: object, **_kw: object) -> None:
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(knp, "_run_one_permission", _fake_run_one)
    record_file = acp_record_path(tmp_path)
    record_file.write_bytes(b"")

    task = asyncio.create_task(
        knp.supervise_kiro_permission_mirror(
            base_url="http://t",
            headers={},
            session_id="conv_3",
            bridge_dir=tmp_path,
            poll_interval_s=0.001,
        )
    )
    try:
        await asyncio.sleep(0.05)
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(_permission_msg("req-1")))
        await asyncio.wait_for(started.wait(), 2.0)
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(_permission_result_msg("req-1"), direction="in"))
        for _ in range(400):
            if created and getattr(created[0], "posts", None):
                break
            await asyncio.sleep(0.005)
        assert created
        url, body = created[0].posts[0]  # type: ignore[attr-defined]
        assert url == "/v1/sessions/conv_3/events"
        assert body["type"] == "external_elicitation_resolved"
        assert body["data"]["elicitation_id"] == kiro_permission_elicitation_id("conv_3", "req-1")
        await asyncio.wait_for(cancelled.wait(), 2.0)
    finally:
        release.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_supervise_mirror_skips_request_resolved_in_same_poll_batch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    created: list[object] = []

    class _FakeAsyncClient:
        def __init__(self, **_kw: object) -> None:
            self.posts: list[tuple[str, dict]] = []
            created.append(self)

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, url: str, *, json: dict, **_kw: object) -> httpx.Response:
            self.posts.append((url, json))
            return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(knp.httpx, "AsyncClient", _FakeAsyncClient)
    run_one_calls: list[str] = []

    async def _fake_run_one(_client: object, *, permission: object, **_kw: object) -> None:
        run_one_calls.append(permission.request_id)  # type: ignore[attr-defined]

    monkeypatch.setattr(knp, "_run_one_permission", _fake_run_one)
    record_file = acp_record_path(tmp_path)
    record_file.write_bytes(b"")

    task = asyncio.create_task(
        knp.supervise_kiro_permission_mirror(
            base_url="http://t",
            headers={},
            session_id="conv_4",
            bridge_dir=tmp_path,
            poll_interval_s=0.02,
        )
    )
    try:
        await asyncio.sleep(0.08)
        with record_file.open("ab") as handle:
            handle.write(
                _record_bytes(_permission_msg("req-1"))
                + _record_bytes(_permission_result_msg("req-1"), direction="in")
            )
        await asyncio.sleep(0.2)
        assert run_one_calls == []
        assert created
        assert created[0].posts == []  # type: ignore[attr-defined]
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_supervise_mirror_serializes_keystroke_delivery_via_coordinator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The coordinator — not the poll loop — is what now serializes delivery.

    Before the ``_DeliveryCoordinator`` refactor (e1a2f802), the poll loop
    itself held a single "pending" slot and would not even start a second
    request's task until the first was done. Now every new request gets its
    own task immediately (see the ``pending`` dict in
    :func:`supervise_kiro_permission_mirror`); what's serialized is only the
    tmux keystroke delivery inside :func:`_run_one_permission`, gated by
    ``coordinator.wait_turn()``. This drives the real ``_run_one_permission``
    (rather than mocking it away, which would bypass the coordinator
    entirely) and blocks the first request's ``send_kiro_permission_verdict``
    call to prove the second request's call cannot start until the first
    one's keystroke delivery finishes *and* Kiro's ACP "response" event for
    it is observed — release now waits for that event rather than firing the
    instant the mocked call returns, so ``_fake_send`` simulates it.
    """

    class _FakeAsyncClient:
        def __init__(self, **_kw: object) -> None:
            pass

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, url: str, *, json: dict, **_kw: object) -> httpx.Response:
            if "native-permission-request" in url:
                return httpx.Response(200, json={"action": "accept"})
            return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(knp.httpx, "AsyncClient", _FakeAsyncClient)

    delivery_order: list[int] = []
    first_call_blocking = threading.Event()
    release_first = threading.Event()
    record_file = acp_record_path(tmp_path)
    record_file.write_bytes(b"")

    def _fake_send(bridge_dir: Path, *, action: str, **_kw: object) -> None:
        # Runs off the event loop thread (via asyncio.to_thread), so blocking
        # here does not stall req-2's task from reaching its own
        # coordinator.wait_turn() — only from getting PAST it.
        index = len(delivery_order)
        delivery_order.append(index)
        if index == 0:
            first_call_blocking.set()
            assert release_first.wait(timeout=2.0), "test never released the first delivery"
            # The coordinator slot is now only released by Kiro's own ACP
            # "response" event (see _run_one_permission's finally), not by
            # this call simply returning — so simulate the TUI confirming
            # req-1 was answered, same as the real kiro_session_forwarder
            # would append to this file once Kiro repaints past the prompt.
            with record_file.open("ab") as handle:
                handle.write(_record_bytes(_permission_result_msg("req-1"), direction="in"))

    monkeypatch.setattr(knp, "send_kiro_permission_verdict", _fake_send)

    task = asyncio.create_task(
        knp.supervise_kiro_permission_mirror(
            base_url="http://t",
            headers={},
            session_id="conv_5",
            bridge_dir=tmp_path,
            poll_interval_s=0.001,
        )
    )
    try:
        await asyncio.sleep(0.05)
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(_permission_msg("req-1")))
        await asyncio.wait_for(asyncio.to_thread(first_call_blocking.wait, 2.0), timeout=2.0)
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(_permission_msg("req-2")))
        await asyncio.sleep(0.05)
        # req-2's task reached wait_turn() but cannot deliver its keystroke
        # yet — req-1 still holds the coordinator slot.
        assert delivery_order == [0]

        release_first.set()
        for _ in range(400):
            if delivery_order == [0, 1]:
                break
            await asyncio.sleep(0.005)
        assert delivery_order == [0, 1]
    finally:
        release_first.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_supervise_mirror_reaps_finished_task_and_mirrors_next_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A finished delivery task frees the slot so a later prompt is still mirrored.

    Without reaping done tasks, a completed (or failed) web-delivery would keep
    the single-prompt slot occupied forever and silently block every later
    prompt from the web mirror.
    """

    class _FakeAsyncClient:
        def __init__(self, **_kw: object) -> None:
            pass

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, url: str, *, json: dict, **_kw: object) -> httpx.Response:
            return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(knp.httpx, "AsyncClient", _FakeAsyncClient)
    run_one_calls: list[str] = []

    async def _fake_run_one(_client: object, *, permission: object, **_kw: object) -> None:
        # Returns immediately, so the parked task finishes without a recorder
        # response event ever arriving (mimics a delivered/failed verdict).
        run_one_calls.append(permission.request_id)  # type: ignore[attr-defined]

    monkeypatch.setattr(knp, "_run_one_permission", _fake_run_one)
    record_file = acp_record_path(tmp_path)
    record_file.write_bytes(b"")

    task = asyncio.create_task(
        knp.supervise_kiro_permission_mirror(
            base_url="http://t",
            headers={},
            session_id="conv_6",
            bridge_dir=tmp_path,
            poll_interval_s=0.001,
        )
    )
    try:
        await asyncio.sleep(0.05)
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(_permission_msg("req-1")))
        for _ in range(400):
            if run_one_calls == ["req-1"]:
                break
            await asyncio.sleep(0.005)
        assert run_one_calls == ["req-1"]
        # No response event for req-1 ever arrives; the reaper must still free
        # the slot once its task is done so req-2 gets mirrored.
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(_permission_msg("req-2")))
        for _ in range(400):
            if run_one_calls == ["req-1", "req-2"]:
                break
            await asyncio.sleep(0.005)
        assert run_one_calls == ["req-1", "req-2"]
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_supervise_mirror_threads_subagent_names_into_run_one_permission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The poll loop must build subagent_names from list_update lines and pass it on.

    Unit tests for _run_one_permission and _read_new_permission_events cover
    their own logic in isolation, but neither proves supervise_kiro_permission_mirror
    actually wires a "_kiro.dev/subagent/list_update" announcement through to
    the delivery task for a request that arrives afterward in a later poll
    tick — that accumulation (subagent_names.update(...) across ticks, then
    passed into _run_one_permission) is this test's only subject.
    """

    class _FakeAsyncClient:
        def __init__(self, **_kw: object) -> None:
            pass

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *_args: object) -> bool:
            return False

        async def post(self, url: str, *, json: dict, **_kw: object) -> httpx.Response:
            return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(knp.httpx, "AsyncClient", _FakeAsyncClient)
    seen_subagent_names: list[dict[str, str]] = []

    async def _fake_run_one(
        _client: object, *, subagent_names: dict[str, str], **_kw: object
    ) -> None:
        # Snapshot now — subagent_names is the loop's live mutable dict and
        # keeps growing after this call returns.
        seen_subagent_names.append(dict(subagent_names))

    monkeypatch.setattr(knp, "_run_one_permission", _fake_run_one)
    record_file = acp_record_path(tmp_path)
    record_file.write_bytes(b"")

    task = asyncio.create_task(
        knp.supervise_kiro_permission_mirror(
            base_url="http://t",
            headers={},
            session_id="conv_7",
            bridge_dir=tmp_path,
            poll_interval_s=0.001,
        )
    )
    try:
        await asyncio.sleep(0.05)
        # Kiro announces the subagent crew (sleep1's own ACP sessionId)
        # before it ever asks for a tool-call permission.
        list_update = {
            "jsonrpc": "2.0",
            "method": "_kiro.dev/subagent/list_update",
            "params": {"subagents": [{"sessionId": "sess-1", "sessionName": "sleep1"}]},
        }
        subagent_request = _permission_msg("req-1")
        subagent_request["params"]["sessionId"] = "sess-1"
        with record_file.open("ab") as handle:
            handle.write(_record_bytes(list_update))
            handle.write(_record_bytes(subagent_request))
        for _ in range(400):
            if seen_subagent_names:
                break
            await asyncio.sleep(0.005)
        assert seen_subagent_names == [{"sess-1": "sleep1"}]
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
