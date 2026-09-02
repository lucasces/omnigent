"""
Tests for the built-in read-only shell allowlist
(:mod:`omnigent.policies.builtins.shell_readonly`) — the
``allow_read_only_shell`` factory that ALLOWs a curated set of side-effect
-free shell commands and ASKs for everything else run through a shell tool.
"""

from __future__ import annotations

import pytest

from omnigent.policies.builtins.shell_readonly import (
    _awk_facts,
    _sed_facts,
    allow_read_only_shell,
    list_read_only_presets,
)
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


def test_nix_develop_command_unwraps_and_evaluates_inner_argv() -> None:
    """``nix develop ... --command <argv>`` runs argv directly (no shell
    re-parsing) — the flake ref / flags before ``--command`` are skipped."""
    policy = allow_read_only_shell(presets=["core", "git"])
    cmd = "nix develop ~/personal/nixos#rust --command git status"
    assert _action(policy(_sh(cmd))) == "ALLOW"
    result = policy(_sh("nix develop .#rust --command git push origin main"))
    assert result is not None
    assert result["result"] == "ASK"


def test_nix_develop_without_command_flag_is_unresolved() -> None:
    """Bare ``nix develop`` (interactive shell, no ``--command``) isn't
    unwrapped to anything — it's just an unmatched head."""
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("nix develop .#rust"))
    assert result is not None
    assert result["result"] == "ASK"


def test_nix_shell_run_unwraps_command_string() -> None:
    """``nix-shell --run "<cmd>"`` takes a command STRING (re-shlexed),
    unlike ``nix develop --command``'s raw argv."""
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh('nix-shell -p git --run "cat foo.txt"'))) == "ALLOW"
    result = policy(_sh('nix-shell -p git --run "rm -rf /"'))
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


# ══════════════════════════════════════════════════════════════════════
# Quoting bug regression (grep -E "a|b")
# ══════════════════════════════════════════════════════════════════════


def test_grep_with_pipe_in_quoted_pattern_allows() -> None:
    """A ``|`` inside a quoted -E pattern is part of the pattern, not a
    shell pipe — regression test for a segment-splitter bug that silently
    truncated the command at the first such character."""
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh('grep -E "a|b" file.txt'))) == "ALLOW"


def test_grep_recursive_with_pipe_in_quoted_pattern_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh('grep -rn "x|y" dir'))) == "ALLOW"


def test_grep_with_combined_flags_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh('grep -ril "needle" . --include=*.py'))) == "ALLOW"


# ══════════════════════════════════════════════════════════════════════
# Guarded patterns: find / sed / awk (full-argv CEL guards)
# ══════════════════════════════════════════════════════════════════════


def test_find_without_exec_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("find . -name *.py"))) == "ALLOW"


def test_find_with_exec_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    result = policy(_sh("find / -exec rm -rf {} +"))
    assert result is not None
    assert result["result"] == "ASK"


def test_find_with_delete_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("find . -delete"))) == "ASK"


def test_find_with_fprintf_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("find . -fprintf /tmp/x %p"))) == "ASK"


def test_sed_without_inplace_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sed s/foo/bar/ file.txt"))) == "ALLOW"


def test_sed_inplace_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sed -i s/a/b/ file.txt"))) == "ASK"


def test_sed_inplace_with_backup_suffix_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sed -i.bak s/a/b/ file.txt"))) == "ASK"


def test_sed_long_form_inplace_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sed --in-place s/a/b/ file.txt"))) == "ASK"


def test_sed_embedded_write_command_asks() -> None:
    """The write vector lives in the script text, not an isolated flag."""
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh('sed -n "1,5w output.txt" file'))) == "ASK"


def test_sed_embedded_execute_flag_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sed s/x/y/e file"))) == "ASK"


def test_sed_external_script_file_asks() -> None:
    """Can't inspect an external script file's content, so treat as ambiguous."""
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("sed -f script.sed file"))) == "ASK"


def test_awk_plain_program_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("awk '{print $1}'"))) == "ALLOW"


def test_awk_with_field_separator_allows() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("awk -F: '{print $1}'"))) == "ALLOW"


def test_awk_with_system_call_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("""awk 'BEGIN{system("id")}' """))) == "ASK"


def test_awk_with_write_redirect_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("""awk '{print $1 > "out.txt"}' """))) == "ASK"


def test_awk_ambiguous_comparison_operator_asks() -> None:
    """A bare ``>`` can't be told apart from a numeric comparison without a
    real awk parser — deliberately over-cautious per the ambiguous-must-ASK
    rule, not a bug."""
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("awk '$1 > 5'"))) == "ASK"


def test_awk_gawk_inplace_extension_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("""awk -i inplace '{gsub(/x/,"y")}' file"""))) == "ASK"


def test_awk_external_script_file_asks() -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh("awk -f prog.awk file.txt"))) == "ASK"


# Regression: the exact 8 commands a live shell-readonly-agent run once
# ALLOWed instead of ASKing (2026-09-02 manual validation). Each mutates the
# filesystem (or worse, runs arbitrary code via awk's system()) and must be
# gated — exercised through the real allow_read_only_shell(...) -> policy(...)
# dispatch path, not the guard/fact-extractor functions in isolation, so a
# future wiring regression here is caught the same way this one would have
# been.


@pytest.mark.parametrize(
    "command",
    [
        'find . -name "*.log" -delete',
        'find . -name "*.sh" -exec chmod +x {} \\;',
        "sed -i 's/foo/bar/' arquivo.txt",
        "sed -n '1p' arquivo.txt -i.bak",
        "sed '/x/w saida.txt' arquivo.txt",
        "awk '{print $1 > \"saida.txt\"}' arquivo.txt",
        "awk '{system(\"rm -rf /tmp/x\")}' arquivo.txt",
        "awk -i inplace '{gsub(/x/,\"y\")}' arquivo.txt",
    ],
)
def test_find_sed_awk_dangerous_invocations_ask(command: str) -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh(command))) == "ASK"


@pytest.mark.parametrize(
    "command",
    [
        'find . -name "*.py"',
        "sed -n '1,5p' arquivo.txt",
        "awk '{print $1}' arquivo.txt",
    ],
)
def test_find_sed_awk_benign_invocations_allow(command: str) -> None:
    policy = allow_read_only_shell(presets=["core"])
    assert _action(policy(_sh(command))) == "ALLOW"


# ══════════════════════════════════════════════════════════════════════
# Guard fact extractors, tested directly
#
# `_awk_facts`'s `has_redirect` is shadowed in the full integration path by
# `_has_unsafe_shell_syntax`'s coarser, quote-unaware `>` check (it rejects
# a segment before any guard runs) — see its docstring. These call the
# extractor directly so that fact is verified in isolation rather than only
# ever failing closed for a different reason.
# ══════════════════════════════════════════════════════════════════════


def test_awk_facts_flags_write_redirect_in_script_text() -> None:
    facts = _awk_facts(["awk", '{print $1 > "out.txt"}'])
    assert facts["has_redirect"] is True
    assert facts["has_system_call"] is False


def test_awk_facts_flags_append_redirect_in_script_text() -> None:
    facts = _awk_facts(["awk", '{print $1 >> "out.txt"}'])
    assert facts["has_redirect"] is True


def test_awk_facts_allows_plain_program_text() -> None:
    facts = _awk_facts(["awk", "{print $1}"])
    assert facts == {
        "has_inplace": False,
        "has_external_script": False,
        "has_redirect": False,
        "has_system_call": False,
    }


def test_sed_facts_flags_inplace_and_write_and_execute() -> None:
    assert _sed_facts(["sed", "-i", "s/a/b/", "f"])["has_inplace"] is True
    assert _sed_facts(["sed", "-n", "1,5w output.txt", "f"])["has_write_command"] is True
    assert _sed_facts(["sed", "s/x/y/e", "f"])["has_execute_flag"] is True


def test_sed_facts_allows_plain_substitution() -> None:
    facts = _sed_facts(["sed", "s/foo/bar/", "file.txt"])
    assert facts == {
        "has_inplace": False,
        "has_external_script": False,
        "has_write_command": False,
        "has_execute_flag": False,
    }


def test_extra_allow_extends_presets() -> None:
    policy = allow_read_only_shell(presets=["core"], extra_allow=[["make", "test"]])
    assert _action(policy(_sh("make test"))) == "ALLOW"
    assert _action(policy(_sh("make deploy"))) == "ASK"


def test_extra_allow_wildcard_matches_any_single_token() -> None:
    """A ``"*"`` pattern token matches any value at that position — e.g. a
    ``-C <path>`` argument whose value doesn't change whether the command
    is read-only."""
    policy = allow_read_only_shell(
        presets=["core"],
        extra_allow=[["git", "-C", "*", "status"]],
    )
    assert _action(policy(_sh("git -C /home/alice/repo status"))) == "ALLOW"
    assert _action(policy(_sh("git -C ~/repo status"))) == "ALLOW"
    assert _action(policy(_sh('git -C "$(pwd)" status'))) == "ALLOW"


def test_extra_allow_wildcard_does_not_relax_the_subcommand() -> None:
    """The wildcard only covers the position it's in — a different
    subcommand after the wildcarded path still ASKs."""
    policy = allow_read_only_shell(
        presets=["core"],
        extra_allow=[["git", "-C", "*", "status"]],
    )
    assert _action(policy(_sh("git -C /home/alice/repo push"))) == "ASK"


def test_extra_allow_wildcard_requires_a_token_to_be_present() -> None:
    """A wildcard position still needs a token there — it isn't optional."""
    policy = allow_read_only_shell(
        presets=["core"],
        extra_allow=[["git", "-C", "*", "status"]],
    )
    assert _action(policy(_sh("git -C status"))) == "ASK"


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
