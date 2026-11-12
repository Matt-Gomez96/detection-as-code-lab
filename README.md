# Detection-as-Code lab

[![CI](https://github.com/Matt-Gomez96/detection-as-code-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Matt-Gomez96/detection-as-code-lab/actions/workflows/ci.yml)

Windows detection rules written as code: every change is **validated**, **converted to Splunk SPL** and **tested against real attack logs** automatically.

```
rules/*.yml (Sigma) ──► sigma check ──► pySigma ─┬─► Splunk backend ──► splunk/*.spl
                                                 └─► SQLite backend ──► tests: real attack logs
                                                                        + benign look-alikes
```

## Rules

| Rule | MITRE ATT&CK | Log source | Level |
|---|---|---|---|
| [Windows Security Event Log Cleared](rules/windows/win_security_log_cleared.yml) → [SPL](splunk/win_security_log_cleared.spl) | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) Clear Windows Event Logs (formerly T1070.001) | Security, event 1102 | high |
| [Windows Event Log Cleared](rules/windows/win_system_eventlog_cleared.yml) → [SPL](splunk/win_system_eventlog_cleared.spl) | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) Clear Windows Event Logs (formerly T1070.001) | System, event 104 | high |
| [PowerShell Executed With an Encoded Command](rules/windows/win_powershell_encoded_command.yml) → [SPL](splunk/win_powershell_encoded_command.spl) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell | Process creation (Sysmon 1) | medium |

Each rule has a test case in [`tests/cases/`](tests/cases/):

- **Attack samples**: public EVTX logs and the *exact* number of events the rule must match in each (so it must fire on the attack and stay silent on the other events in the same log).
- **Attack variants** (optional): invented events that must match, covering what the public samples lack (e.g. `-e`, `/enc`, Unicode dashes, renamed `powershell.exe`).
- **Benign events**: realistic look-alikes that must *not* match (e.g. `-ExecutionPolicy`, which also starts with `-e`; `certutil -encode`), with the reason written next to each one.

Example of why this matters: dropping the trailing space in `' -e '` would make the PowerShell rule fire on every `-ExecutionPolicy Bypass`; the benign tests catch it.

## How it works

1. **Validate**: [`sigma check`](https://github.com/SigmaHQ/sigma-cli) verifies syntax, conditions and that the ATT&CK tags exist in the current ATT&CK release.
2. **Convert**: the [pySigma](https://github.com/SigmaHQ/pySigma) Splunk backend turns each rule into SPL in [`splunk/`](splunk/). The SPL is committed so it can be reviewed in pull requests; CI fails if it is out of date.
3. **Test**: the pySigma SQLite backend turns each rule into SQL. Events from the attack logs are loaded into an in-memory SQLite table and the query must return exactly the expected events. Same idea as a SIEM search, but it runs anywhere in seconds.

Both conversions use the same log-source assumptions (processing pipelines), so a rule that passes the tests targets the same logs in Splunk.

## Run it locally

Requires [uv](https://docs.astral.sh/uv/) (it installs the right Python version by itself).

```bash
uv sync                                  # install the exact dependency versions
uv run sigma check rules/                # validate the rules
uv run detlab convert                    # regenerate splunk/*.spl
uv run pytest                            # run all tests

uv run detlab show <log.evtx>            # print events as flat fields (to design a rule)
uv run detlab run <rule.yml> <log.evtx>  # run a rule against any log
uv run detlab sql <rule.yml>             # see the SQL the local engine runs
```

## Design decisions

- **Attack samples are never committed.** They are downloaded at test time from a pinned commit and verified by SHA-256 ([`datasets.yml`](datasets.yml)): reproducible, tamper-evident, and respectful of the datasets' licences.
- **A local engine instead of a SIEM** for the test loop: fast and free, and it runs the same on a laptop and in CI. Running the generated SPL in a real Splunk is on the roadmap.
- **Hardened CI**: third-party GitHub Actions pinned to commit SHAs, read-only token.
- **Known gap**: Sigma field names (e.g. `Provider_Name`) do not always match the field names of a given Splunk deployment; validating the SPL against real Splunk will close it.

## Roadmap

- [x] T1685.005 Clear Windows Event Logs (Security 1102 and System 104)
- [x] T1059.001 PowerShell with an encoded command
- [ ] T1003.001 LSASS memory access
- [ ] T1543.003 Service creation
- [ ] T1053.005 Scheduled task creation
- [ ] Test the generated SPL in Splunk (Docker)
- [ ] ATT&CK Navigator coverage layer

## Credits and licence

- Attack samples: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden (GPL-3.0), downloaded at test time and not redistributed here.
- Tooling: [Sigma](https://github.com/SigmaHQ/sigma), [pySigma](https://github.com/SigmaHQ/pySigma) and [sigma-cli](https://github.com/SigmaHQ/sigma-cli) by SigmaHQ; [evtx](https://github.com/omerbenamram/evtx) parser by Omer Ben-Amram.
- Code and rules in this repository: [MIT](LICENSE).
