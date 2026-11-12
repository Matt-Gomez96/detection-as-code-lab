"""Unit tests for mutation edits and verdicts (detlab.mutation)."""

import pytest

from detlab.mutation import MutationError, apply, problem

RULE = """detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -e '
            - ' -enc '
    condition: selection
"""


def test_delete_removes_the_whole_line():
    assert "-enc" not in apply(RULE, [{"delete": "' -enc '"}])
    assert apply(RULE, [{"delete": "' -enc '"}]).count("\n") == RULE.count("\n") - 1


def test_delete_removes_the_nested_lines_too():
    mutant = apply(RULE, [{"delete": "CommandLine|contains"}])
    assert mutant == (
        "detection:\n"
        "    selection:\n"
        "        Image|endswith: '\\powershell.exe'\n"
        "    condition: selection\n"
    )


def test_replace_changes_only_the_text():
    mutant = apply(RULE, [{"replace": "' -e '", "with": "' -e'"}])
    assert "- ' -e'\n" in mutant
    assert "' -enc '" in mutant


def test_edits_apply_in_order():
    mutant = apply(RULE, [{"replace": "' -e '", "with": "' -x '"}, {"delete": "' -x '"}])
    assert "-x" not in mutant and "-e " not in mutant


@pytest.mark.parametrize(
    "edit",
    [{"delete": "' -ec '"}, {"replace": "pwsh", "with": "x"}],
    ids=["delete", "replace"],
)
def test_text_not_in_rule_is_an_error(edit):
    with pytest.raises(MutationError, match="is not in the rule"):
        apply(RULE, [edit])


def test_ambiguous_text_is_an_error():
    # " -e" is inside both ' -e ' and ' -enc ': the edit could hit the wrong line.
    with pytest.raises(MutationError, match="appears 2 times"):
        apply(RULE, [{"delete": " -e"}])


@pytest.mark.parametrize("edits", [[], [{"remove": "x"}], [{"replace": "x"}]])
def test_malformed_mutation_is_an_error(edits):
    with pytest.raises(MutationError):
        apply(RULE, edits)


def test_a_killed_mutation_is_fine():
    assert problem({"why": "x"}, ["benign event matched: y"]) is None


def test_a_surviving_mutation_is_a_problem():
    assert "mutation survived" in problem({"why": "x"}, [])


def test_a_declared_survivor_is_fine_while_it_survives():
    assert problem({"why": "x", "survives": "defensive"}, []) is None
    assert "remove 'survives'" in problem({"why": "x", "survives": "defensive"}, ["z"])
