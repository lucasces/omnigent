"""The declarative builtin ACP CLI harness catalog (omnigent/acp_cli_harnesses.py).

Two halves:

- Mechanism tests drive a fake catalog row through the shared spawn-env builder
  and the runner dispatch, so the machinery stays covered even while the
  catalog is small.
- Per-row tests parametrize over the real catalog and assert every derived
  registration a row relies on, so adding a row is one dict entry and this
  module proves the wiring end to end.
"""

from __future__ import annotations

import dataclasses
import json
import shlex
from pathlib import Path

import pytest

from omnigent.acp_cli_harnesses import ACP_CLI_HARNESSES, AcpCliHarness
from omnigent.harness_aliases import canonicalize_harness
from omnigent.harness_install_spec import HarnessInstallSpec
from omnigent.harness_plugins import (
    harness_capabilities,
    harness_install_keys,
    harness_labels,
    harness_modules,
    install_specs,
    valid_harnesses,
)
from omnigent.inner.datamodel import OSEnvSandboxSpec, OSEnvSpec
from omnigent.onboarding.harness_install import ui_setup_steps
from omnigent.runtime.workflow import _build_acp_cli_spawn_env
from omnigent.spec.types import AgentSpec, ExecutorSpec

_FAKE_ROW = AcpCliHarness(
    install=HarnessInstallSpec(
        "Fake CLI",
        "fakecli",
        None,
        login_args=("login", "--device"),
        install_hint="curl -fsSL https://fake.example/install.sh | bash",
    ),
    args=("agent", "stdio"),
    aliases=("fake-cli",),
)


def _spec(
    harness: str,
    os_env: OSEnvSpec | None = None,
    *,
    permission_mode: str | None = None,
) -> AgentSpec:
    config: dict[str, object] = {"harness": harness}
    if permission_mode is not None:
        config["permission_mode"] = permission_mode
    return AgentSpec(
        spec_version=1,
        name=f"test-{harness}",
        instructions="Test agent.",
        executor=ExecutorSpec(type="omnigent", config=config),
        os_env=os_env,
    )


# ---------------------------------------------------------------------------
# Mechanism (fake row)
# ---------------------------------------------------------------------------


def test_spawn_env_forwards_cwd_sandbox_and_quotes_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shared builder forwards session cwd + os_env and shell-quotes argv0.

    These are exactly the fields a hand-rolled thin wrap historically dropped
    (a spec sandbox silently ignored, the session folder falling back to the
    runner workspace), so the catalog path must prove them.
    """
    monkeypatch.setitem(ACP_CLI_HARNESSES, "fakecli", _FAKE_ROW)
    monkeypatch.delenv("OMNIGENT_FAKECLI_PATH", raising=False)
    # A resolved binary path containing a space must survive the round-trip
    # through the shlex-split command string.
    monkeypatch.setattr(
        "omnigent._platform.resolve_cli_binary",
        lambda name, **k: "/opt/fake cli/fakecli" if name == "fakecli" else None,
    )
    os_env = OSEnvSpec(
        type="caller_process",
        cwd=None,
        sandbox=OSEnvSandboxSpec(type="omnibox"),
        fork=False,
    )
    env = _build_acp_cli_spawn_env(
        _spec("fakecli", os_env=os_env), harness="fakecli", cwd=Path("/work/space")
    )

    assert shlex.split(env["HARNESS_ACP_COMMAND"]) == [
        "/opt/fake cli/fakecli",
        "agent",
        "stdio",
    ]
    assert env["HARNESS_ACP_NAME"] == "Fake CLI"
    assert env["HARNESS_ACP_CWD"] == "/work/space"
    assert json.loads(env["HARNESS_ACP_OS_ENV"]) == dataclasses.asdict(os_env)
    # Rows own their model selection: no model var may ride along.
    assert "HARNESS_ACP_MODEL" not in env


def test_spawn_env_honors_path_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ACP_CLI_HARNESSES, "fakecli", _FAKE_ROW)
    monkeypatch.setenv("OMNIGENT_FAKECLI_PATH", "/custom/fakecli")
    env = _build_acp_cli_spawn_env(_spec("fakecli"), harness="fakecli")
    assert shlex.split(env["HARNESS_ACP_COMMAND"])[0] == "/custom/fakecli"
    # No session cwd and no os_env on the spec: neither var may be emitted, so
    # the wrap falls back to OMNIGENT_RUNNER_WORKSPACE / its own default.
    assert "HARNESS_ACP_CWD" not in env
    assert "HARNESS_ACP_OS_ENV" not in env


def test_runner_dispatch_routes_catalog_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """_build_spawn_env_from_spec picks up any catalog row without new wiring."""
    from omnigent.runner.app import _build_spawn_env_from_spec

    monkeypatch.setitem(ACP_CLI_HARNESSES, "fakecli", _FAKE_ROW)
    monkeypatch.delenv("OMNIGENT_FAKECLI_PATH", raising=False)
    env = _build_spawn_env_from_spec(_spec("fakecli"), "fakecli")
    assert env is not None
    assert env["HARNESS_ACP_NAME"] == "Fake CLI"
    assert shlex.split(env["HARNESS_ACP_COMMAND"])[-2:] == ["agent", "stdio"]


def test_fake_row_login_command() -> None:
    assert _FAKE_ROW.login_command == "fakecli login --device"
    assert _FAKE_ROW.label == "Fake CLI"
    assert _FAKE_ROW.binary == "fakecli"


def test_spawn_env_mirrors_row_omnigent_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rows that opt out of MCP injection must propagate that to the wrap.

    A vendor CLI that rejects ``session/new`` mcpServers (jcode) fails every
    session if the Omnigent MCP server is advertised, so the row flag has to
    reach ``HARNESS_ACP_OMNIGENT_MCP`` rather than relying on the wrap's
    default-on.
    """
    no_mcp_row = dataclasses.replace(_FAKE_ROW, omnigent_mcp=False)
    monkeypatch.setitem(ACP_CLI_HARNESSES, "fakecli", no_mcp_row)
    env = _build_acp_cli_spawn_env(_spec("fakecli"), harness="fakecli")
    assert env["HARNESS_ACP_OMNIGENT_MCP"] == "0"

    monkeypatch.setitem(ACP_CLI_HARNESSES, "fakecli", _FAKE_ROW)
    env = _build_acp_cli_spawn_env(_spec("fakecli"), harness="fakecli")
    assert env["HARNESS_ACP_OMNIGENT_MCP"] == "1"


# ---------------------------------------------------------------------------
# Per-row registration (parametrized over the real catalog)
# ---------------------------------------------------------------------------


# Rows whose vendor behavior earns their own thin wrap, which injects an
# AcpExtension into the same shared ACP executor (see omnigent.inner.devin).
# Listing one here is deliberate: it declares that the row no longer runs the
# shared wrap and may declare capabilities the generic profile does not.
_VENDOR_WRAPS = {"devin": "omnigent.inner.devin.harness"}


@pytest.mark.parametrize("name", sorted(ACP_CLI_HARNESSES))
def test_catalog_row_is_fully_registered(name: str) -> None:
    """One catalog row must yield every registration a harness needs."""
    row = ACP_CLI_HARNESSES[name]

    assert name in valid_harnesses()
    assert harness_labels()[name] == row.label
    assert harness_modules()[name] == _VENDOR_WRAPS.get(name, "omnigent.inner.acp_harness")

    caps = harness_capabilities()
    if name in _VENDOR_WRAPS:
        # A vendor wrap injects an AcpExtension, so the row may declare more than
        # the generic profile — but only on the axes that extension implements.
        # Normalizing those back must reproduce "acp" exactly, so a vendor cannot
        # quietly diverge on resume, auth, effort, or anything else.
        assert caps[name].subagents is True, name
        assert dataclasses.replace(caps[name], subagents=caps["acp"].subagents) == caps["acp"]
    else:
        # Same declared profile as the generic "acp" harness they run through.
        assert caps[name] == caps["acp"]
    assert install_specs()[name] == row.install
    for spelling in (name, *row.aliases):
        assert harness_install_keys()[spelling] == name
    for alias in row.aliases:
        assert canonicalize_harness(alias) == name
    # The setup checklist must exist, and rows with a vendor login must show it.
    steps = ui_setup_steps(name)
    assert steps
    if row.login_command is not None and row.install.package is not None:
        assert any(step.command == row.login_command for step in steps)
    # `omni setup` renders a row per catalog entry and needs somewhere to point a
    # user who hasn't installed the CLI. Without one the row would say "Not
    # installed" with no way to fix it.
    assert row.install.install_hint or row.install.package


@pytest.mark.parametrize("name", sorted(ACP_CLI_HARNESSES))
def test_catalog_row_spawn_env_builds(name: str) -> None:
    """The shared builder produces a launchable command for every real row."""
    row = ACP_CLI_HARNESSES[name]
    env = _build_acp_cli_spawn_env(_spec(name), harness=name)
    argv = shlex.split(env["HARNESS_ACP_COMMAND"])
    assert argv[0], "argv[0] must resolve to a non-empty binary"
    if row.args:
        assert argv[-len(row.args) :] == list(row.args)
    assert env["HARNESS_ACP_NAME"] == row.label
    assert env["HARNESS_ACP_OMNIGENT_MCP"] == ("1" if row.omnigent_mcp else "0")


# ---------------------------------------------------------------------------
# `omni setup` drill-in
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(ACP_CLI_HARNESSES))
def test_setup_drill_in_names_install_and_login(
    name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Selecting a builtin ACP row in ``omni setup`` names how to install and sign in.

    These rows own their auth and install out-of-band, so the drill-in is the only
    place a user learns the two commands. Without it the row is a dead end — which
    is what shipped before: ``grok`` was addressable via ``--harness grok`` but
    absent from setup entirely, making a builtin *less* discoverable than a
    user-configured ``acp:`` entry.

    **What breaks if this fails**: a user picks the harness in setup and is told
    nothing about how to make it work.
    """
    from omnigent import cli_config

    row = ACP_CLI_HARNESSES[name]
    # Force the "not installed" branch so the install hint has to be shown.
    monkeypatch.setattr("omnigent._platform.resolve_cli_binary", lambda _binary: None)
    cli_config._show_acp_cli_harness(name)

    out = capsys.readouterr().out
    assert row.label in out
    assert (row.install.install_hint or row.binary) in out
    if row.login_command:
        assert row.login_command in out
    # Tells the user how to actually launch it.
    assert f"--harness {name}" in out


def test_setup_drill_in_ignores_unknown_row() -> None:
    """A stale key (concurrent config change) must not raise."""
    from omnigent import cli_config

    cli_config._show_acp_cli_harness("definitely-not-a-row")


def test_spawn_env_forwards_permission_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """A builtin row honors ``permission_mode`` too, not just configured agents.

    Devin and Grok Build are builtin rows, so they take this builder rather than
    ``_build_acp_spawn_env``. Missing it here would leave the option working for
    a self-registered ``acp:devin`` but silently inert for the builtin ``devin``
    the picker offers.
    """
    monkeypatch.setitem(ACP_CLI_HARNESSES, "fakecli", _FAKE_ROW)
    monkeypatch.setattr(
        "omnigent._platform.resolve_cli_binary", lambda _b, **k: "/usr/bin/fakecli"
    )

    env = _build_acp_cli_spawn_env(
        _spec("fakecli", permission_mode="bypassPermissions"), harness="fakecli"
    )
    assert env["HARNESS_ACP_PERMISSION_MODE"] == "bypassPermissions"
    # Absent -> unset, so the wrap keeps its prompting default.
    assert "HARNESS_ACP_PERMISSION_MODE" not in _build_acp_cli_spawn_env(
        _spec("fakecli"), harness="fakecli"
    )


# ---------------------------------------------------------------------------
# kiro-acp: the one row that carries a per-session agent profile
# ---------------------------------------------------------------------------


def _kiro_spec(instructions: str) -> AgentSpec:
    return AgentSpec(
        spec_version=1,
        name="kiro-acp-test",
        instructions=instructions,
        executor=ExecutorSpec(type="omnigent", config={"harness": "kiro-acp"}),
    )


def test_kiro_acp_row_writes_a_profile_and_selects_it(tmp_path: Path) -> None:
    """The persona reaches kiro through ``--agent``, not the first user turn.

    kiro-cli takes its persona, MCP servers and pre-authorized ``allowedTools``
    from the ``--agent`` profile; verified against a live kiro-cli 2.20.1 ACP
    session, where a profile-backed agent answered as its profile persona while
    the injected system prompt did not reach it.
    """
    env = _build_acp_cli_spawn_env(
        _kiro_spec("You are a spike specialist."),
        harness="kiro-acp",
        cwd=tmp_path,
        session_id="sess-1",
    )
    argv = shlex.split(env["HARNESS_ACP_COMMAND"])
    assert argv[1] == "acp"
    assert "--agent" in argv

    profile_name = argv[argv.index("--agent") + 1]
    profile = tmp_path / ".kiro" / "agents" / f"{profile_name}.json"
    assert profile.is_file()
    payload = json.loads(profile.read_text())
    assert payload["name"] == profile_name
    assert payload["prompt"] == "You are a spike specialist."
    # Orchestration/read tools stay pre-authorized so they don't raise a card.
    assert "@omnigent/sys_session_create" in payload["allowedTools"]

    # The persona is delivered once, by the profile.
    assert env["HARNESS_ACP_INJECT_SYSTEM_PROMPT"] == "0"
    # kiro ignores session/new.mcpServers, so the relay is not advertised there.
    assert env["HARNESS_ACP_OMNIGENT_MCP"] == "0"


def test_kiro_acp_profile_name_is_stable_per_session(tmp_path: Path) -> None:
    """Two sessions in one workspace get their own file and never collide."""
    one = _build_acp_cli_spawn_env(
        _kiro_spec("A"), harness="kiro-acp", cwd=tmp_path, session_id="sess-a"
    )
    two = _build_acp_cli_spawn_env(
        _kiro_spec("B"), harness="kiro-acp", cwd=tmp_path, session_id="sess-b"
    )
    assert one["HARNESS_ACP_COMMAND"] != two["HARNESS_ACP_COMMAND"]
    assert len(list((tmp_path / ".kiro" / "agents").glob("*.json"))) == 2

    # Deterministic from the session id alone, so teardown can re-derive it.
    again = _build_acp_cli_spawn_env(
        _kiro_spec("A"), harness="kiro-acp", cwd=tmp_path, session_id="sess-a"
    )
    assert again["HARNESS_ACP_COMMAND"] == one["HARNESS_ACP_COMMAND"]


def test_kiro_acp_without_instructions_uses_kiros_default_agent(tmp_path: Path) -> None:
    """Nothing to say, nothing to write -- and no dangling ``--agent``."""
    env = _build_acp_cli_spawn_env(
        _kiro_spec(""), harness="kiro-acp", cwd=tmp_path, session_id="sess-bare"
    )
    assert "--agent" not in env["HARNESS_ACP_COMMAND"]
    assert not (tmp_path / ".kiro" / "agents").exists()
    assert "HARNESS_ACP_INJECT_SYSTEM_PROMPT" not in env


def test_kiro_acp_without_a_session_id_writes_nothing(tmp_path: Path) -> None:
    """The profile name is keyed by session id; no id means no profile."""
    env = _build_acp_cli_spawn_env(
        _kiro_spec("You are a spike specialist."), harness="kiro-acp", cwd=tmp_path
    )
    assert "--agent" not in env["HARNESS_ACP_COMMAND"]
    assert not (tmp_path / ".kiro" / "agents").exists()


def test_kiro_acp_profile_is_registered_for_teardown(tmp_path: Path) -> None:
    """Teardown removes the file, so it can't linger in the user's workspace."""
    from omnigent.runner.native.orchestration import _KIRO_AGENT_PROFILE_FILES

    _build_acp_cli_spawn_env(
        _kiro_spec("You are a spike specialist."),
        harness="kiro-acp",
        cwd=tmp_path,
        session_id="sess-teardown",
    )
    try:
        path = _KIRO_AGENT_PROFILE_FILES.get("sess-teardown")
        assert path is not None and path.is_file()
    finally:
        _KIRO_AGENT_PROFILE_FILES.pop("sess-teardown", None)


@pytest.mark.parametrize("harness", sorted(set(ACP_CLI_HARNESSES) - {"kiro-acp"}))
def test_other_rows_get_no_agent_profile(harness: str, tmp_path: Path) -> None:
    """Only the kiro row opts in; every other row is byte-identical to before."""
    env = _build_acp_cli_spawn_env(
        _spec(harness), harness=harness, cwd=tmp_path, session_id="sess-x"
    )
    assert "--agent" not in env["HARNESS_ACP_COMMAND"]
    assert not (tmp_path / ".kiro").exists()
