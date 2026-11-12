"""Tests for every Sigma rule in rules/.

Each rule ``rules/**/<name>.yml`` needs a test case ``tests/cases/<name>.yml`` with:

- ``samples``: public attack logs and the exact number of events the rule must
  match in each one (at least one sample with matches > 0);
- ``benign_events``: realistic events that must not match (at least one).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from detlab import convert, engine, samples
from detlab.events import load_events, normalize

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
BENIGN_CASES = [
    pytest.param(rule, benign, id=f"{rule.stem}:{benign['name']}")
    for rule, benign in case_items("benign_events")
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


def test_every_test_case_has_a_rule():
    rule_names = {rule.stem for rule in RULES}
    orphans = [case.name for case in CASES.glob("*.yml") if case.stem not in rule_names]
    assert not orphans, f"test cases without a rule: {orphans}"


@pytest.mark.parametrize("rule, sample", SAMPLE_CASES)
def test_attack_sample(rule: Path, sample: dict):
    log = samples.fetch(ROOT, sample["source"], sample["file"], sample["sha256"])
    events = load_events(log)
    matches = engine.match(rule, events)
    assert len(matches) == sample["expected_matches"], (
        f"{len(matches)} of {len(events)} events matched, "
        f"expected {sample['expected_matches']}"
    )


@pytest.mark.parametrize("rule, benign", BENIGN_CASES)
def test_benign_event_does_not_match(rule: Path, benign: dict):
    matches = engine.match(rule, [normalize(benign["event"])])
    assert not matches, f"false positive: {benign['why']}"


def test_splunk_queries_are_up_to_date():
    result = convert.convert_all(ROOT, check=True)
    problems = [p.relative_to(ROOT).as_posix() for p in [*result.outdated, *result.stale]]
    assert not problems, f"run `uv run detlab convert` and commit: {problems}"
