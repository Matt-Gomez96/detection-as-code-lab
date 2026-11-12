"""Run Sigma rules locally against events, using SQLite as the search engine.

1. pySigma converts the rule into SQL (the official ``sqlite`` backend).
2. The events are loaded into an in-memory SQLite table called ``logs``.
3. The query runs; the rows it returns are the events the rule matched.

Same idea as in a SIEM (Sigma -> query language -> search over the logs), but it
runs anywhere Python runs: on a laptop and in GitHub Actions.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from detlab.events import Event
from detlab.pipelines import local_pipeline

TABLE = "logs"  # table name used by the pySigma sqlite backend
_MISSING_COLUMN = re.compile(r"no such column: (.+)$")


def load_rule(rule_path: str | Path) -> SigmaCollection:
    return SigmaCollection.from_yaml(Path(rule_path).read_text(encoding="utf-8"))


def to_sql(rule_path: str | Path) -> list[str]:
    """Convert a Sigma rule file to SQLite queries (one per rule in the file)."""
    backend = sqliteBackend(processing_pipeline=local_pipeline())
    return backend.convert(load_rule(rule_path))


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _load(events: Iterable[Event]) -> sqlite3.Connection:
    events = list(events)
    # SQLite column names are case-insensitive: "ProcessId" (event 4663) and
    # "ProcessID" (event 5156) are the same column, so keep one spelling of each.
    columns = sorted({field.lower(): field for event in events for field in event}.values())
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    # COLLATE NOCASE: Sigma string matching is case-insensitive, also for "=".
    # No column type on purpose: numbers stay numbers (EventID=1102) and text stays text.
    definition = ", ".join(f"{_quote(c)} COLLATE NOCASE" for c in columns) or '"_empty"'
    con.execute(f"CREATE TABLE {TABLE} ({definition})")
    for event in events:
        names = list(event)
        if not names:
            continue
        placeholders = ", ".join("?" for _ in names)
        con.execute(
            f"INSERT INTO {TABLE} ({', '.join(_quote(n) for n in names)}) VALUES ({placeholders})",
            [event[n] for n in names],
        )
    return con


def _run(con: sqlite3.Connection, query: str) -> list[Event]:
    # A rule may ask for a field that no loaded event has. In a SIEM that field is
    # simply empty, so add it as an empty column and try again.
    for _ in range(50):
        try:
            return [dict(row) for row in con.execute(query)]
        except sqlite3.OperationalError as error:
            missing = _MISSING_COLUMN.search(str(error))
            if not missing:
                raise
            column = missing.group(1).strip().strip("`\"'[]")
            con.execute(f"ALTER TABLE {TABLE} ADD COLUMN {_quote(column)} COLLATE NOCASE")
    raise RuntimeError(f"Too many missing columns for query: {query}")


def match(rule_path: str | Path, events: Iterable[Event]) -> list[Event]:
    """Return the events matched by the rule(s) in ``rule_path``."""
    con = _load(events)
    try:
        matches: list[Event] = []
        for query in to_sql(rule_path):
            matches += _run(con, query)
        return [{k: v for k, v in event.items() if v is not None} for event in matches]
    finally:
        con.close()
