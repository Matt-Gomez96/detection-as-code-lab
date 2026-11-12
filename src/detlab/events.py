"""Load Windows events and flatten them into simple ``field -> value`` records.

Sigma rules for Windows refer to fields by short names (``EventID``, ``Channel``,
``Provider_Name``, ``CommandLine``...). A raw EVTX record is nested XML, so each
record is flattened to one level using those names:

- ``System`` header -> ``EventID``, ``Channel``, ``Computer``, ``Provider_Name``...
- ``EventData`` / ``UserData`` -> one field per data item (``SubjectUserName``...).

If a data item has the same name as a header field (event 104 has a ``Channel``
item with the name of the log that was cleared), the header keeps the plain name
and the data item is stored as ``<Container>_<name>``, e.g. ``UserData_Channel``.
Names are compared case-insensitively (``ProcessID`` and ``ProcessId`` clash).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from evtx import PyEvtxParser

Event = dict[str, Any]


def _attributes(node: Any) -> dict[str, Any]:
    if isinstance(node, dict):
        return node.get("#attributes") or {}
    return {}


def _value(value: Any) -> Any:
    """Unwrap ``{"#attributes": ..., "#text": x}`` and serialise nested data."""
    if isinstance(value, dict) and "#text" in value:
        value = value["#text"]
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return value


def _items(node: Any) -> Iterator[tuple[str, Any]]:
    """Yield the named children of an XML-like node, skipping ``#attributes``."""
    if isinstance(node, dict):
        for name, value in node.items():
            if not name.startswith("#"):
                yield name, value


def flatten_record(record: dict[str, Any]) -> Event:
    """Flatten one EVTX record (as produced by the ``evtx`` parser) into a flat event."""
    event = record.get("Event", record)
    system = event.get("System") or {}

    flat: Event = {
        "EventID": _value(system.get("EventID")),
        "Channel": system.get("Channel"),
        "Computer": system.get("Computer"),
        "Provider_Name": _attributes(system.get("Provider")).get("Name"),
        "Provider_Guid": _attributes(system.get("Provider")).get("Guid"),
        "Level": system.get("Level"),
        "Task": system.get("Task"),
        "Keywords": system.get("Keywords"),
        "EventRecordID": system.get("EventRecordID"),
        "TimeCreated": _attributes(system.get("TimeCreated")).get("SystemTime"),
        # PID/TID of the process that *wrote* the event (often the event log service).
        # Prefixed so they never clash with EventData's ProcessId, which rules use.
        "Execution_ProcessID": _attributes(system.get("Execution")).get("ProcessID"),
        "Execution_ThreadID": _attributes(system.get("Execution")).get("ThreadID"),
        "UserID": _attributes(system.get("Security")).get("UserID"),
    }

    data_items: list[tuple[str, str, Any]] = [
        ("EventData", name, value) for name, value in _items(event.get("EventData"))
    ]
    # UserData wraps its fields in one extra element, e.g. <LogFileCleared>.
    for _, child in _items(event.get("UserData")):
        data_items += [("UserData", name, value) for name, value in _items(child)]

    # Field names are compared case-insensitively, like SQLite columns and Splunk fields.
    taken = {key.lower() for key in flat}
    for container, name, value in data_items:
        key = f"{container}_{name}" if name.lower() in taken else name
        taken.add(key.lower())
        flat[key] = _value(value)

    return {key: value for key, value in flat.items() if value is not None}


def load_evtx(path: str | Path) -> list[Event]:
    parser = PyEvtxParser(str(path))
    return [flatten_record(json.loads(record["data"])) for record in parser.records_json()]


def normalize(raw: dict[str, Any]) -> Event:
    """Accept either a raw EVTX-style record (with ``Event``/``System``) or a flat event."""
    if "Event" in raw or "System" in raw:
        return flatten_record(raw)
    return dict(raw)


def load_events(path: str | Path) -> list[Event]:
    """Load events from ``.evtx``, ``.json`` (list or JSON lines) or ``.yml``/``.yaml`` (list)."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        return load_evtx(path)
    text = path.read_text(encoding="utf-8")
    if suffix == ".json":
        stripped = text.lstrip()
        if stripped.startswith("["):
            raw_events = json.loads(text)
        else:
            raw_events = [json.loads(line) for line in text.splitlines() if line.strip()]
    elif suffix in (".yml", ".yaml"):
        raw_events = yaml.safe_load(text) or []
    else:
        raise ValueError(f"Unsupported log format: {path.name} (use .evtx, .json or .yml)")
    return [normalize(raw) for raw in raw_events]
