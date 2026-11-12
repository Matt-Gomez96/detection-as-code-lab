"""Processing pipelines: how generic Sigma log sources map to concrete logs.

A Sigma rule says *what* to look for (``logsource`` + ``detection``). A pipeline
adds the details of a specific environment, for example:

- ``sysmon``: ``category: process_creation`` means Sysmon Event ID 1.
- ``windows-logsources``: ``service: security`` means ``Channel = 'Security'``.
- ``splunk_windows``: ``service: security`` means ``source="WinEventLog:Security"``
  and ``EventID`` is called ``EventCode`` in Splunk.

The local test engine and the Splunk conversion use the same log-source
assumptions (Sysmon for process/registry/file events, Windows channels for the
rest), so a rule that passes the tests targets the same logs in Splunk.
"""

from __future__ import annotations

from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.processing.pipeline import ProcessingPipeline


def local_pipeline() -> ProcessingPipeline:
    """Pipeline for the local SQLite test engine (fields keep their EVTX names)."""
    return sysmon_pipeline() + windows_logsource_pipeline()


def splunk_pipeline() -> ProcessingPipeline:
    """Pipeline for Splunk (Windows event logs ingested with the Splunk Add-on for Windows)."""
    return sysmon_pipeline() + splunk_windows_pipeline()
