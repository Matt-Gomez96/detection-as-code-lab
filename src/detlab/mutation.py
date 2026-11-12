"""Mutation testing: break a rule on purpose and check that its test case notices.

Each test case can declare ``mutations``: deliberately broken versions of the rule,
each one a plausible mistake or a design decision undone. A mutation is a list of
text edits applied to the rule file:

- ``delete: <text>`` removes the line that contains <text>, together with the
  lines nested under it (indented further), so a whole YAML node goes at once:
  ``delete: 'SourceImage|startswith'`` removes that key and its list of values;
- ``replace: <text>`` + ``with: <text>`` swaps <text> for something else.

Each <text> must appear exactly once in the rule (after the previous edits), so an
edit can never hit the wrong line by accident.

The test case "kills" a mutation when at least one of its checks fails on the
broken rule: a sample with a different number of matches, a missed attack variant
or a benign event that matches. A mutation nobody kills means that part of the rule
has no test: add one, or remove that part if it adds nothing. A mutation that is
expected to survive says so with ``survives: <reason>``, so that it stays visible.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from detlab import engine
from detlab.events import Event, normalize


class MutationError(ValueError):
    """A mutation that cannot be applied as written."""


def _check_unique(text: str, count: int) -> None:
    if count == 0:
        raise MutationError(f"{text!r} is not in the rule")
    if count > 1:
        raise MutationError(f"{text!r} appears {count} times in the rule; make it more specific")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _delete_node(lines: list[str], start: int) -> list[str]:
    """Remove ``lines[start]`` and the lines nested under it."""
    end = start + 1
    while end < len(lines) and (
        not lines[end].strip() or _indent(lines[end]) > _indent(lines[start])
    ):
        end += 1
    return lines[:start] + lines[end:]


def apply(rule_text: str, edits: list[dict]) -> str:
    """Return ``rule_text`` with the mutation's edits applied, in order."""
    if not edits:
        raise MutationError("a mutation needs at least one edit")
    for edit in edits:
        if "delete" in edit:
            lines = rule_text.splitlines(keepends=True)
            hits = [i for i, line in enumerate(lines) if edit["delete"] in line]
            _check_unique(edit["delete"], len(hits))
            rule_text = "".join(_delete_node(lines, hits[0]))
        elif "replace" in edit and "with" in edit:
            _check_unique(edit["replace"], rule_text.count(edit["replace"]))
            rule_text = rule_text.replace(edit["replace"], edit["with"])
        else:
            raise MutationError(f"unknown edit {edit!r}: use 'delete', or 'replace' + 'with'")
    return rule_text


def problem(mutant: dict, failures: list[str]) -> str | None:
    """What is wrong with this mutation's outcome, or None if it is as declared."""
    if "survives" in mutant:
        if failures:
            return (
                f"expected to survive ({mutant['survives']}), but it is now killed by "
                f"{failures}: remove 'survives' from the mutation"
            )
        return None
    if not failures:
        return (
            f"mutation survived, no check noticed it ({mutant['why']}). "
            "Add a test that catches it, or remove that part of the rule if it adds nothing"
        )
    return None


def case_failures(
    rule: engine.Rule, case: dict, sample_events: Callable[[dict], list[Event]]
) -> list[str]:
    """Run a whole test case against ``rule``; return every check that fails.

    ``sample_events`` returns the events of one entry of ``samples``.
    """
    failures = []
    for sample in case.get("samples") or []:
        found = len(engine.match(rule, sample_events(sample)))
        if found != sample["expected_matches"]:
            failures.append(
                f"sample {Path(sample['file']).name}: {found} matches, "
                f"expected {sample['expected_matches']}"
            )
    for attack in case.get("attack_events") or []:
        if len(engine.match(rule, [normalize(attack["event"])])) != 1:
            failures.append(f"attack variant missed: {attack['name']}")
    for benign in case.get("benign_events") or []:
        if engine.match(rule, [normalize(benign["event"])]):
            failures.append(f"benign event matched: {benign['name']}")
    return failures
