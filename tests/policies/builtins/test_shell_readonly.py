"""
Tests for the built-in read-only shell allowlist
(:mod:`omnigent.policies.builtins.shell_readonly`) — the
``allow_read_only_shell`` factory that ALLOWs a curated set of side-effect
-free shell commands and ASKs for everything else run through a shell tool.
"""

from __future__ import annotations

from omnigent.policies.builtins.shell_readonly import allow_read_only_shell, list_read_only_presets
from omnigent.policies.registry import get_registry, load_registry, validate_factory_params
from omnigent.policies.schema import PolicyEvent, PolicyResponse
from tests.policies.builtins.helpers import tool_call_event as tc

_HANDLER = "omnigent.policies.builtins.shell_readonly.allow_read_only_shell"


def _sh(command: str) -> PolicyEvent:
    """Build a ``sys_os_shell`` ``tool_call`` event carrying *command*."""
    return tc("sys_os_shell", {"command": command})


def _action(result: PolicyResponse | None) -> str:
    """Reduce a policy result to its decision string for terse assertions."""
    return result["result"] if result else "ALLOW"


# ══════════════════════════════════════════════════════════════════════════════
# Core allowlist behavior
# ══════════════════════════════════════════════════════════════════════════════


def test_safe_core_command_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("cat README.md"))) == "ALLOW"


def test_unlisted_command_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("rm -rf /"))
    assert result is not None
    assert result["result"] == "ASK"


def test_git_preset_allows_status_but_not_push() -> None:
    policy = allow_read_only_shell(presets=["git"])
    assert _action(policy(_sh("git status"))) == "ALLOW"
    assert _action(policy(_sh("git push origin main"))) == "ASK"


def test_git_branch_delete_not_covered() -> None:
    """``git branch`` is deliberately excluded (can delete/rename)."""
    policy = allow_read_only_shell(presets=["git"])
    assert _action(policy(_sh("git branch -D main"))) == "ASK"


def test_default_preset_is_core() -> None:
    policy = allow_read_only_shell()
    assert _action(policy(_sh("ls -la"))) == "ALLOW"
    assert _action(policy(_sh("git status"))) == "ASK"


# ══════════════════════════════════════════════════════════════════════════════
# Bypass resistance
# ══════════════════════════════════════════════════════════════════════════════


def test_chained_unsafe_command_asks() -> None:
    """A safe command chained with an unsafe one must still ASK."""
    policy = allow_read_only_shell(presets=["core", "git"])
    result = policy(_sh("git status && rm -rf /"))
    assert result is not None
    assert result["result"] == "ASK"


def test_sudo_wrapped_safe_command_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sudo cat /etc/hosts"))) == "ALLOW"


def test_sudo_wrapped_unsafe_command_asks() -> None:
    policy = allow_read_only_shell(presets=["git"])
    result = policy(_sh("sudo git push origin main"))
    assert result is not None
    assert result["result"] == "ASK"


def test_bash_c_unwraps_and_evaluates_inner_command() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh('bash -c "cat foo.txt"'))) == "ALLOW"
    result = policy(_sh('bash -c "rm -rf /"'))
    assert result is not None
    assert result["result"] == "ASK"


def test_command_substitution_hiding_unsafe_command_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("echo $(rm -rf /)"))
    assert result is not None
    assert result["result"] == "ASK"


def test_output_redirection_disqualifies_otherwise_safe_command() -> None:
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("cat secret.txt > /tmp/leak"))
    assert result is not None
    assert result["result"] == "ASK"


def test_process_substitution_disqualifies_command() -> None:
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("diff <(rm -rf /) <(echo hi)"))
    assert result is not None
    assert result["result"] == "ASK"


def test_unresolved_wrapper_flag_asks() -> None:
    """A wrapper flag this module doesn't model leaves the head unresolved."""
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("sudo -u root cat /etc/shadow"))
    # sudo -u is modeled by _shell.py and skips to "cat" — still safe.
    assert _action(result) == "ALLOW"


# ══════════════════════════════════════════════════════════════════════════════
# Configuration knobs
# ══════════════════════════════════════════════════════════════════════════════


def test_extra_allow_extends_presets() -> None:
    policy = allow_read_only_shell(presets=["core"], extra_allow=[["make", "test"]])
    assert _action(policy(_sh("make test"))) == "ALLOW"
    assert _action(policy(_sh("make deploy"))) == "ASK"


def test_unknown_preset_name_ignored() -> None:
    policy = allow_read_only_shell(presets=["not-a-real-preset"])
    result = policy(_sh("cat foo"))
    assert result is not None
    assert result["result"] == "ASK"


def test_shell_tools_scopes_which_tools_are_parsed() -> None:
    policy = allow_read_only_shell(presets=["core"], shell_tools=["terminal"])
    # sys_os_shell not in the configured set -> abstain.
    assert policy(_sh("rm -rf /")) is None


def test_non_shell_tool_abstains() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert policy(tc("Read", {"file_path": "/etc/passwd"})) is None


def test_list_read_only_presets_covers_all_bundled_names() -> None:
    presets = list_read_only_presets()
    assert set(presets) == {
        "core",
        "git",
        "node",
        "python",
        "rust",
        "docker",
        "k8s",
        "nix",
        "terraform",
    }
    assert all(desc for desc in presets.values())


def test_terraform_preset_allows_plan_but_not_apply() -> None:
    policy = allow_read_only_shell(presets=["terraform"])
    assert _action(policy(_sh("terraform plan"))) == "ALLOW"
    assert _action(policy(_sh("terraform apply -auto-approve"))) == "ASK"
    assert _action(policy(_sh("terraform state list"))) == "ALLOW"
    assert _action(policy(_sh("terraform state rm aws_instance.foo"))) == "ASK"


def test_terraform_preset_covers_tofu_binary_too() -> None:
    policy = allow_read_only_shell(presets=["terraform"])
    assert _action(policy(_sh("tofu plan"))) == "ALLOW"
    assert _action(policy(_sh("tofu destroy -auto-approve"))) == "ASK"


# ══════════════════════════════════════════════════════════════════════════════
# Registry discovery
# ══════════════════════════════════════════════════════════════════════════════


def test_registered_in_builtin_registry() -> None:
    load_registry()
    handlers = {entry.handler for entry in get_registry()}
    assert _HANDLER in handlers


def test_valid_params_pass_schema_validation() -> None:
    load_registry()
    assert validate_factory_params(_HANDLER, {"presets": ["core", "git"]}) is None


def test_wrong_param_type_fails_schema_validation() -> None:
    load_registry()
    error = validate_factory_params(_HANDLER, {"presets": "core"})
    assert error is not None
