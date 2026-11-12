"""Unit tests for event flattening and the local SQLite engine."""

from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection

from detlab import engine
from detlab.events import flatten_record

RULE = """
title: Test rule
id: 00000000-0000-4000-8000-000000000000
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        TargetUserName: Administrator
    filter:
        IpAddress|startswith: '10.'
    condition: selection and not filter
level: low
"""


def write_rule(tmp_path: Path) -> Path:
    path = tmp_path / "rule.yml"
    path.write_text(RULE, encoding="utf-8")
    return path


def test_flatten_system_and_user_data():
    record = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Eventlog"}},
                "EventID": {"#attributes": {"Qualifiers": 0}, "#text": 104},
                "Channel": "System",
                "Execution": {"#attributes": {"ProcessID": 812, "ThreadID": 1}},
            },
            "UserData": {
                "LogFileCleared": {
                    "#attributes": {"xmlns": "x"},
                    "SubjectUserName": "user01",
                    "Channel": "Application",
                }
            },
        }
    }
    event = flatten_record(record)
    assert event["EventID"] == 104
    assert event["Provider_Name"] == "Microsoft-Windows-Eventlog"
    assert event["Channel"] == "System"  # the header wins...
    assert event["UserData_Channel"] == "Application"  # ...the data item is renamed
    assert event["SubjectUserName"] == "user01"
    assert event["Execution_ProcessID"] == 812


def test_flatten_name_clash_is_case_insensitive():
    record = {
        "Event": {
            "System": {"EventID": 1, "Channel": "Security"},
            "EventData": {"channel": "x"},
        }
    }
    event = flatten_record(record)
    assert event["Channel"] == "Security"
    assert event["EventData_channel"] == "x"


def test_match_is_case_insensitive_and_respects_channel(tmp_path):
    rule = write_rule(tmp_path)
    events = [
        {"EventID": 4625, "Channel": "Security", "TargetUserName": "administrator", "IpAddress": "203.0.113.5"},
        {"EventID": 4625, "Channel": "Security", "TargetUserName": "Administrator", "IpAddress": "10.0.0.5"},
        {"EventID": 4625, "Channel": "System", "TargetUserName": "Administrator"},
    ]
    matches = engine.match(rule, events)
    assert [m["IpAddress"] for m in matches] == ["203.0.113.5"]


def test_missing_fields_do_not_break_the_query(tmp_path):
    rule = write_rule(tmp_path)
    events = [{"EventID": 4625, "Channel": "Security", "TargetUserName": "Administrator"}]
    # IpAddress does not exist in any event: the filter cannot apply, so it matches.
    assert len(engine.match(rule, events)) == 1


def test_columns_differing_only_in_case(tmp_path):
    rule = write_rule(tmp_path)
    events = [
        {"EventID": 4663, "Channel": "Security", "ProcessId": "0x1"},
        {"EventID": 5156, "Channel": "Security", "ProcessID": 4},
    ]
    assert engine.match(rule, events) == []


def test_a_loaded_rule_can_be_converted_many_times():
    # pySigma applies the processing pipeline to the rule object while converting;
    # the engine must convert a copy, or the log condition would be added again.
    rule = SigmaCollection.from_yaml(RULE)
    first, second = engine.to_sql(rule), engine.to_sql(rule)
    assert first == second
    assert second[0].count("Channel='Security'") == 1
