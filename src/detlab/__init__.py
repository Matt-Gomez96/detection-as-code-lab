"""detlab: tooling for the Detection-as-Code lab.

- events:  load Windows logs (EVTX, JSON, YAML) as flat field -> value records.
- engine:  run Sigma rules locally against those records (via SQLite).
- convert: convert Sigma rules to Splunk SPL.
- samples: download public attack samples, pinned and verified by SHA-256.
"""
