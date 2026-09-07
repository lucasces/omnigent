"""
Tests for :func:`omnigent.policies.builtins._shell.split_command_segments`,
specifically its quote-awareness.
"""

from __future__ import annotations

from omnigent.policies.builtins._shell import split_command_segments


def test_pipe_inside_double_quoted_pattern_is_not_a_chain_operator() -> None:
    """Regression test: a ``|`` inside a quoted regex argument (e.g.
    ``grep -E "a|b"``) must stay part of that segment, not be mistaken for a
    shell pipe and silently truncate the command."""
    assert split_command_segments('grep -E "a|b" file.txt') == ['grep -E "a|b" file.txt']


def test_pipe_inside_double_quoted_pattern_with_recursive_flags() -> None:
    assert split_command_segments('grep -rn "x|y" dir') == ['grep -rn "x|y" dir']


def test_semicolon_inside_single_quotes_is_not_a_chain_operator() -> None:
    assert split_command_segments("echo 'a;b|c' && ls") == ["echo 'a;b|c'", "ls"]


def test_ampersand_inside_quotes_is_not_a_chain_operator() -> None:
    assert split_command_segments('echo "a & b"') == ['echo "a & b"']


def test_real_chaining_operators_still_split_outside_quotes() -> None:
    assert split_command_segments("git status && ls") == ["git status", "ls"]
    assert split_command_segments("git status; ls") == ["git status", "ls"]
    assert split_command_segments("git status || ls") == ["git status", "ls"]


def test_lone_background_ampersand_still_splits() -> None:
    assert split_command_segments("echo hi & git push") == ["echo hi", "git push"]


def test_fd_merge_ampersand_is_not_a_chain_operator() -> None:
    """Regression test: `&` glued to `>` (fd-dup / merged-stream redirects)
    must stay part of the segment, not be mistaken for the background/
    chaining `&` and shredded into nonsense pieces (`ls 2>` + `1`)."""
    assert split_command_segments("ls 2>&1") == ["ls 2>&1"]
    assert split_command_segments("ls 1>&2") == ["ls 1>&2"]
    assert split_command_segments("ls > /dev/null 2>&1") == ["ls > /dev/null 2>&1"]
    assert split_command_segments("ls &> /dev/null") == ["ls &> /dev/null"]


def test_fd_merge_ampersand_does_not_hide_a_chained_command() -> None:
    """A real background/chain `&` right after an fd-merge redirect must
    still split — only the `&` glued to `<`/`>` is exempted."""
    assert split_command_segments("ls 2>&1 & git push") == ["ls 2>&1", "git push"]


def test_unterminated_quote_does_not_crash_and_merges_to_one_segment() -> None:
    """A malformed / unterminated quote is treated as extending to the end
    of the string rather than raising — fail-closed, since the merged
    segment then fails to tokenize or match downstream."""
    assert split_command_segments('echo "a && b') == ['echo "a && b']


def test_escaped_double_quote_inside_double_quotes_does_not_end_the_quote() -> None:
    assert split_command_segments('grep "a\\"|b" file') == ['grep "a\\"|b" file']


def test_command_substitution_body_still_split_recursively() -> None:
    assert split_command_segments("echo $(git status && ls)") == [
        "echo",
        "git status",
        "ls",
    ]
