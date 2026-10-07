# HunterScope

Identity-centric triage for SOC L1/L2: give it a **user** or **host** and a **time range**, get an
investigation dossier with correlated detections, an **explainable risk score**, MITRE ATT&CK mapping,
extracted IOCs, a timeline, and an optional **pseudonymized** export that is safe to paste into a ticket.

Works fully offline on JSON/NDJSON exports (Entra ID sign-ins, M365 Unified Audit Log, Windows/Sysmon).

```
logs (json/ndjson) -> ingest (normalize to Event) -> detect (stateful rules) -> score (explainable)
                                                                         \-> report (Jinja2 md/json) -> redact (optional)
```

## Quick start

```bash
pip install -e ".[dev]"
python scripts/generate_samples.py           # synthetic data, already committed
S=data/samples
hunterscope triage -i $S/entra_signins.ndjson -i $S/ual_audit.ndjson -i $S/windows_sysmon.ndjson -u jkowalski -t 24h
hunterscope triage ... -u jkowalski --redact -o ticket.md      # safe to share
hunterscope triage ... -H ws-jkowalski                         # host view
hunterscope rules                                              # rules + MITRE mapping
pytest -q
```

`--anchor latest` (default) ends the window at the target's newest event, which is what you want for exported
data; use `--anchor now` against live exports.

## Detections (stateful correlation; `src/hunterscope/config/rules.yaml`)

| Rule | Tactic | MITRE |
|---|---|---|
| failures_then_success | credential-access | T1110, T1078 |
| mfa_fatigue | credential-access | T1621 |
| impossible_travel | initial-access | T1078 |
| off_hours_login | initial-access | T1078 |
| suspicious_inbox_rule | collection | T1114.003, T1564.008 |
| oauth_consent | persistence | T1528 |
| lotl_commandline | execution | T1059 (+ per pattern: T1027, T1105, T1003.001, T1033, T1490, ...) |

Thresholds, weights and patterns are YAML, overridable with `--config`. Every rule ships with positive **and**
benign tests (flight vs impossible travel, 4 vs 5 failures, `certutil -hashfile` vs `-urlcache`).

## Score

Not a bare sum. First hit of a rule counts fully, repeats count 25%, one rule is capped at 2x its weight, and
activity across several ATT&CK tactics adds a bonus. The dossier lists every contribution, so an analyst can
see *why* a user has 73/100.

## Redaction

Single-pass, deterministic pseudonyms (`USER_A`, `INTERNAL_IP_1`, `HOST_2`); the same entity always gets the same
label, so the story stays readable. PESEL is matched only when the checksum is valid. With `--key-env VAR`
labels become HMAC-SHA256 tags: stable across runs and not reversible by brute-forcing small spaces (IPv4, PESEL).
`--mapping-out` writes label -> original and **contains the sensitive data**; keep it out of tickets.

Known limits: free-text names ("Jan Kowalski") are not detected; unknown short hostnames are not detected
(FQDNs are); public IPs are kept by default because they are IOCs, set `keep_public_ips: false`
(`--redactor-config`) before sharing outside the SOC. Your company's egress IP is public too.

## Data

`data/samples/` is synthetic and labelled as such. Do not commit real logs, and do not build this against
employer data.

## Roadmap

- [ ] `.eml` phishing triage (SPF/DKIM/DMARC, defanged URLs, attachment hashes) feeding the same dossier
- [ ] SQLite case store + `--shift-summary` handover (statuses, notes, open anomalies)
- [ ] Sigma rules via pySigma for stateless patterns; ATT&CK coverage table vs public datasets
- [ ] Standalone HTML report; live OpenSearch client (last, after everything works offline)
