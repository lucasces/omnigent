"""Declarative catalog of builtin ACP CLI harnesses.

One row here is one first-class harness backed by a vendor CLI that speaks the
Agent Client Protocol on stdio (the ``goose acp`` / ``qwen --acp`` family).
Rows are pure data; every registration a row needs derives from this table:

- registry entries (validity, module routing, aliases, picker label,
  capabilities, install spec, install keys): ``omnigent/harness_plugins.py``
- readiness: the generic install-key gate in
  ``omnigent/onboarding/harness_readiness.py`` (binary on PATH)
- setup steps and one-click installability:
  ``omnigent/onboarding/harness_install.py``
- spawn env: :func:`omnigent.runtime.workflow._build_acp_cli_spawn_env`
- dispatch: ``_build_spawn_env_from_spec`` in ``omnigent/runner/app.py``
- live e2e matrix exclusion:
  ``tests/e2e/omnigent/test_run_harness_without_agent_e2e.py``

Every row runs through the shared generic wrap
(``omnigent/inner/acp_harness.py``) and :class:`~omnigent.inner.acp_executor.
AcpExecutor` — the same code path a user-configured ``acp:<slug>`` agent uses.
To promote a new ACP-speaking vendor CLI to a builtin harness, add one row and
its docs; do not add a new inner module, registry entries, or a per-harness
spawn-env builder. Rows own their auth and model selection (``OWN_AUTH``): no
Omnigent credential or model override is wired, so a ``/model`` pick is
rejected up front rather than silently dropped.

One consequence worth knowing before adding a row: the generic ACP spawn env is
deny-by-default and a row has no ``env_passthrough`` of its own (only a
user-configured ``acp:<slug>`` agent can declare one), so a row's CLI reaches the
agent with the base environment only. A vendor that configures or authenticates
*solely* from an environment variable therefore needs a user-configured agent
rather than a row here; a vendor that reads stored credentials from disk (Devin,
Grok's OAuth login) works as a row.

This module stays import-light (stdlib + :mod:`omnigent.harness_install_spec`)
so the registry, onboarding, and runner layers can all read it without cycles.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from omnigent.harness_install_spec import HarnessInstallSpec


@dataclass(frozen=True)
class AcpCliHarness:
    """One builtin ACP CLI harness, declared as pure data.

    :param install: Install + auth metadata (display label, binary, optional
        npm package or install hint, vendor login command). The ``binary`` is
        also the readiness gate and the spawn command's argv[0].
    :param args: Argv appended after the binary to start the CLI's ACP stdio
        server, e.g. ``("--acp",)`` or ``("agent", "stdio")``.
    :param aliases: Accepted alternate spellings, canonicalized to the row key.
    :param omnigent_mcp: Whether to offer Omnigent's MCP server in
        ``session/new``. Some vendor CLIs don't yet support session-scoped
        MCP and ignore ``mcpServers``, configuring MCP out of band instead
        (e.g. jcode reads ``~/.jcode/mcp.json``); set ``False`` for those so
        the server isn't advertised.
    :param session_agent_profile: Write a per-session kiro-cli agent profile to
        ``<cwd>/.kiro/agents/<name>.json`` and select it with ``--agent <name>``
        (see :func:`omnigent.runtime.workflow._build_acp_cli_spawn_env`). The
        profile carries the agent's ``instructions`` as its persona, the
        pre-authorized ``allowedTools``, and -- written by the executor just
        before the process starts -- Omnigent's MCP relay, since that profile is
        the only channel kiro-cli reads any of them from. Off for every other
        row.
    """

    install: HarnessInstallSpec
    args: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    omnigent_mcp: bool = True
    session_agent_profile: bool = False

    @property
    def label(self) -> str:
        """Picker/display label, e.g. ``"Grok Build"``."""
        return self.install.display

    @property
    def binary(self) -> str:
        """The vendor CLI binary name, e.g. ``"grok"``."""
        return self.install.binary

    @property
    def login_command(self) -> str | None:
        """The vendor login command to show in setup steps, or ``None``."""
        if self.install.login_args is None:
            return None
        return shlex.join([self.binary, *self.install.login_args])


# Keyed by canonical harness id. Keep keys sorted; each row's registrations
# derive from here (see the module docstring for the full list).
ACP_CLI_HARNESSES: dict[str, AcpCliHarness] = {
    # Devin (Cognition's ``devin`` CLI) drives ``devin acp`` — its ACP stdio
    # server. Ships via a curl installer (not npm) and authenticates through its
    # own ``devin auth login``, which writes a credential file it reads back at
    # spawn; Omnigent stores nothing. The row runs Devin's account-default model:
    # a row carries no per-user model, and ``DEVIN_MODEL`` cannot reach the agent
    # (see the env note above), so pinning a model needs a user-configured
    # ``acp:<slug>`` agent whose command passes ``--model``.
    "devin": AcpCliHarness(
        install=HarnessInstallSpec(
            "Devin",
            "devin",
            None,
            login_args=("auth", "login"),
            install_hint="curl -fsSL https://cli.devin.ai/install.sh | bash",
            auth_hint="run `devin auth login` (Omnigent stores no Devin credential)",
        ),
        args=("acp",),
    ),
    # Grok Build (xAI's ``grok`` CLI) drives ``grok agent stdio``. Ships via a
    # curl installer (not npm) and authenticates through its own ``grok login``
    # (xAI OAuth, device-code capable) or ``XAI_API_KEY``; Omnigent stores no
    # credential.
    "grok": AcpCliHarness(
        install=HarnessInstallSpec(
            "Grok Build",
            "grok",
            None,
            login_args=("login", "--device-auth"),
            install_hint="curl -fsSL https://x.ai/cli/install.sh | bash",
            auth_hint="run `grok login --device-auth` (xAI OAuth) or set XAI_API_KEY",
        ),
        args=("agent", "stdio"),
        aliases=("grok-build",),
    ),
    # Kiro (AWS's ``kiro-cli``) drives ``kiro-cli acp`` -- its headless ACP
    # stdio server, the same binary the ``kiro-native`` TUI harness drives.
    # Additive: ``kiro-native`` keeps working untouched, and an agent opts into
    # this path by declaring ``harness: kiro-acp``.
    #
    # Two divergences from a plain row, both verified against a live kiro-cli
    # 2.20.1 ACP session:
    #  * ``session_agent_profile`` -- kiro takes its persona, its MCP servers
    #    and its pre-authorized ``allowedTools`` from the ``--agent`` profile.
    #  * Omnigent's MCP relay reaches it through that same profile, not through
    #    ``session/new.mcpServers`` -- kiro ignores the latter outright. The
    #    executor writes the relay into the profile before the process starts
    #    (``HARNESS_ACP_MCP_PROFILE``), so ``sys_session_*`` are available from
    #    the very first message.
    "kiro-acp": AcpCliHarness(
        install=HarnessInstallSpec(
            "Kiro (ACP)",
            "kiro-cli",
            None,
            install_hint="curl -fsSL https://cli.kiro.dev/install | bash",
            auth_hint="sign in with `kiro-cli login` (Omnigent stores no Kiro credential)",
        ),
        args=("acp",),
        session_agent_profile=True,
    ),
    # jcode (https://jcode.sh) drives ``jcode acp``. Ships via a curl
    # installer (not npm) and owns its provider/model config in
    # ``~/.jcode/config.toml``; Omnigent stores no credential. Its ACP server
    # ignores ``mcpServers`` in ``session/new`` (session-scoped MCP isn't
    # supported; MCP is configured in ``~/.jcode/mcp.json``), so the Omnigent
    # MCP server is not offered.
    "jcode": AcpCliHarness(
        install=HarnessInstallSpec(
            "Jcode",
            "jcode",
            None,
            install_hint="curl -fsSL https://jcode.sh/install | bash",
            auth_hint="configure a provider in ~/.jcode/config.toml",
        ),
        args=("acp",),
        omnigent_mcp=False,
    ),
}
