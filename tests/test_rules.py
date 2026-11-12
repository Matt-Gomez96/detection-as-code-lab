"""Tests for every Sigma rule in rules/.

Each rule ``rules/**/<name>.yml`` needs a test case ``tests/cases/<name>.yml`` with:

- ``samples``: public attack logs and the exact number of events the rule must
  match in each one (at least one sample with matches > 0);
- ``attack_events`` (optional): invented attack variants that must match, to cover
  what the public samples do not;
- ``benign_events``: realistic events that must not match (at least one);
- ``mutations``: deliberately broken versions of the rule that the checks above
  must notice (at least one; see ``detlab.mutation``).
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import pytest
import yaml

from sigma.collection import SigmaCollection

from detlab import convert, engine, mutation, samples
from detlab.events import Event, load_events, normalize

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "rules").rglob("*.yml"))
CASES = ROOT / "tests" / "cases"

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "references", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level",
]
ATTACK_TECHNIQUE_TAG = re.compile(r"attack\.t\d{4}(\.\d{3})?")


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def case_path(rule: Path) -> Path:
    return CASES / f"{rule.stem}.yml"


@functools.cache
def _load_sample(source: str, file: str, sha256: str) -> tuple[Event, ...]:
    return tuple(load_events(samples.fetch(ROOT, source, file, sha256)))


def sample_events(sample: dict) -> list[Event]:
    """Events of one ``samples`` entry, parsed once per test run."""
    return list(_load_sample(sample["source"], sample["file"], sample["sha256"]))


def case_items(key: str):
    """(rule, item) pairs for every entry under ``key`` in every test case."""
    for rule in RULES:
        if case_path(rule).exists():
            for item in read_yaml(case_path(rule)).get(key) or []:
                yield rule, item


SAMPLE_CASES = [
    pytest.param(rule, sample, id=f"{rule.stem}:{Path(sample['file']).name}")
    for rule, sample in case_items("samples")
]
ATTACK_EVENT_CASES = [
    pytest.param(rule, attack, id=f"{rule.stem}:{attack['name']}")
    for rule, attack in case_items("attack_events")
]
BENIGN_CASES = [
    pytest.param(rule, benign, id=f"{rule.stem}:{benign['name']}")
    for rule, benign in case_items("benign_events")
]
MUTATION_CASES = [
    pytest.param(rule, mutant, id=f"{rule.stem}:{mutant['name']}")
    for rule, mutant in case_items("mutations")
]


def test_there_are_rules():
    assert RULES, "no rules found in rules/"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.stem)
def test_rule_metadata(rule: Path):
    data = read_yaml(rule)
    missing = [field for field in REQUIRED_FIELDS if not data.get(field)]
    assert not missing, f"missing fields: {missing}"
    assert any(ATTACK_TECHNIQUE_TAG.fullmatch(tag) for tag in data["tags"]), (
        "needs an ATT&CK technique tag such as attack.t1070.001"
    )


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.stem)
def test_rule_has_test_case(rule: Path):
    path = case_path(rule)
    assert path.exists(), f"missing test case: {path.relative_to(ROOT).as_posix()}"
    case = read_yaml(path)
    assert any(s["expected_matches"] > 0 for s in case.get("samples") or []), (
        "needs at least one attack sample with expected_matches > 0"
    )
    assert case.get("benign_events"), "needs at least one benign event"
    assert case.get("mutations"), "needs at least one mutation"


def test_every_test_case_has_a_rule():
    rule_names = {rule.stem for rule in RULES}
    orphans = [case.name for case in CASES.glob("*.yml") if case.stem not in rule_names]
    assert not orphans, f"test cases without a rule: {orphans}"


@pytest.mark.parametrize("rule, sample", SAMPLE_CASES)
def test_attack_sample(rule: Path, sample: dict):
    events = sample_events(sample)
    matches = engine.match(rule, events)
    assert len(matches) == sample["expected_matches"], (
        f"{len(matches)} of {len(events)} events matched, "
        f"expected {sample['expected_matches']}"
    )


@pytest.mark.parametrize("rule, attack", ATTACK_EVENT_CASES)
def test_attack_event_matches(rule: Path, attack: dict):
    matches = engine.match(rule, [normalize(attack["event"])])
    assert len(matches) == 1, f"missed attack variant: {attack['why']}"


@pytest.mark.parametrize("rule, benign", BENIGN_CASES)
def test_benign_event_does_not_match(rule: Path, benign: dict):
    matches = engine.match(rule, [normalize(benign["event"])])
    assert not matches, f"false positive: {benign['why']}"


@pytest.mark.parametrize("rule, mutant", MUTATION_CASES)
def test_mutation_is_killed(rule: Path, mutant: dict):
    """The broken rule must make at least one check of the test case fail."""
    broken_text = mutation.apply(rule.read_text(encoding="utf-8"), mutant["edits"])
    try:
        broken = SigmaCollection.from_yaml(broken_text)
        engine.to_sql(broken)
    except Exception as error:  # noqa: BLE001 - any error means the mutant is not a valid rule
        pytest.fail(f"the mutated rule is not valid Sigma, fix the edits: {error!r}")
    failures = mutation.case_failures(broken, read_yaml(case_path(rule)), sample_events)
    problem = mutation.problem(mutant, failures)
    assert problem is None, problem


def test_splunk_queries_are_up_to_date():
    result = convert.convert_all(ROOT, check=True)
    problems = [p.relative_to(ROOT).as_posix() for p in [*result.outdated, *result.stale]]
    assert not problems, f"run `uv run detlab convert` and commit: {problems}"
