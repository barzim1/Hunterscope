# HunterScope reference

Detailed documentation. The short version is in the [README](../README.md).

Contents: [Quick start](#quick-start) · [Reports](#reports) · [Detections](#detections-stateful-correlation-srchunterscopeconfigrulesyaml) ·
[Phishing triage](#phishing-triage) · [Cases and shift handover](#cases-and-shift-handover) ·
[Explaining what you see](#explaining-what-you-see-explain) ·
[Measured coverage](#measured-coverage) · [Score](#score) · [Redaction](#redaction) · [Data](#data) ·
[Roadmap](#roadmap--not-done)

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python scripts/generate_samples.py           # synthetic data, already committed
S=data/samples
hunterscope triage -i $S -u jkowalski -t 24h              # whole directory: logs + emails
hunterscope triage -i $S -u jkowalski --redact -o ticket.md      # safe to share
hunterscope triage -i $S -H ws-jkowalski                         # host view
hunterscope rules                                              # rules + MITRE mapping
pytest -q
```

`--anchor latest` (default) ends the window at the target's newest event, which is what you want for exported
data; use `--anchor now` against live exports.

## Reports

Every dossier and handover can be rendered as Markdown (for tickets), JSON, or a **standalone HTML** file:

```bash
hunterscope triage -i $S -u jkowalski -f html -o dossier.html
hunterscope triage -i $S -u jkowalski -f html --redact -o dossier-shareable.html
hunterscope shift-summary -f html -o handover.html
```

![Dossier: risk score, tactics observed and score breakdown](img/dossier-light.png)

![Dossier in dark mode: findings with evidence](img/dossier-dark-findings.png)

![Shift handover: unresolved, escalated and closed cases](img/handover-light.png)

![The same dossier with --redact: the user becomes USER_A](img/dossier-redacted.png)

Open the generated examples in a browser: [`dossier-jkowalski.html`](examples/dossier-jkowalski.html),
[`dossier-jkowalski-redacted.html`](examples/dossier-jkowalski-redacted.html),
[`handover.html`](examples/handover.html) (synthetic data; download first, GitHub shows source).

Design decisions:
- **No JavaScript and no external requests**, enforced by a `Content-Security-Policy` of `default-src 'none'`. The
  file is safe to attach to a ticket or email and works offline. Print it from the browser for a PDF.
- **Log content is untrusted.** Command lines, subjects and sender names go through Jinja autoescaping; tests feed
  `<script>` and `<img onerror>` payloads through every field.
- **Colour never carries meaning alone.** Severity is a status colour plus a distinct glyph and a text label; the
  risk score is a hero number with a meter and the exact value; the score breakdown is a table whose bars also print
  their points. Follows the OS light/dark setting and prints cleanly.
- The only links are to the MITRE ATT&CK technique pages.

Rebuild the examples and screenshots (deterministic, synthetic): `pip install -e ".[shots]"` then
`python scripts/build_screenshots.py`.

## Detections (stateful correlation; `src/hunterscope/config/rules.yaml`)

| Rule | Tactic | MITRE |
|---|---|---|
| failures_then_success | credential-access | T1110, T1078 |
| mfa_fatigue | credential-access | T1621 |
| impossible_travel | initial-access | T1078 |
| off_hours_login | initial-access | T1078 |
| suspicious_inbox_rule | collection | T1114.003, T1564.008 |
| oauth_consent | persistence | T1528 |
| lsass_access | credential-access | T1003.001 |
| password_spray_ip (cross-account) | credential-access | T1110.003 |
| lotl_commandline | execution | T1059 (+ per pattern: T1027, T1105, T1003.001, T1033, T1490, ...) |
| suspicious_email | initial-access | T1566.001, T1566.002 |
| phish_then_new_signin (meta rule) | initial-access | T1566, T1078 |

Thresholds, weights and patterns are YAML, overridable with `--config`. Every rule ships with positive **and**
benign tests (flight vs impossible travel, 4 vs 5 failures, `certutil -hashfile` vs `-urlcache`).

### Cross-account detection and the IP pivot

Per-user rules cannot see a password spray: it tries one password per account on purpose, so no single account
shows more than one failure. `password_spray_ip` looks across accounts instead. Within a sliding window
(`window_minutes`, default 60) it counts the distinct accounts failing a credential check from one IP; at
`min_accounts` (default 5) it fires, unless the window averages more than `max_attempts_per_account` (default 3.0)
attempts per account, which is brute force and is left to `failures_then_success`. If an attacked account then signs
in from the same IP the finding is `high` and weighs `weight_signed_in` (45) instead of `weight` (30), and the
account is listed as an IOC.

How a single-user dossier can see other accounts: `build_dossier` collects the events of *other* accounts that share
an IP with the target inside the window and hands them to cross-entity rules only as `context`. Every per-user rule
keeps judging the target's own events alone (a test pins this). The dossier also lists those accounts under
"Other accounts from the same IPs".

`hunterscope triage --ip 203.0.113.77` pivots the other way: the target is the address, the timeline is everything
seen from it, and the table lists every account with failure and success counts. `--save` keeps an IP case separate
from the cases of the users involved.

Tuning: `ignore_ips` silences a shared corporate egress, VPN or NAT address where many users legitimately fail
together. The sample data has a benign case (three users mistype once behind the corporate NAT, below threshold).
The window picked for the per-account guard is the longest one with the most accounts, not the first moment the
count is reached.

Validation: synthetic scenarios and adversarial unit tests only. On the public datasets it produced no finding (see
`coverage.md`); the one labelled spray dataset is in the holdout and was not inspected.

### Phishing triage

`.eml` is parsed with the stdlib (`email`, policy.default): SPF/DKIM/DMARC from `Authentication-Results`, origin IP from
the `Received` chain, anchor text vs. real `href`, attachments with SHA-256. Signals are split into **strong**
(auth failure, lookalike/punycode sender, display-name spoofing, risky or double-extension attachment, raw-IP link,
link text pointing elsewhere) and **weak** (Reply-To / Return-Path mismatch, shorteners, lure keywords). One strong
signal fires the rule; weak ones need three together, so a legitimate newsletter with a different Reply-To stays quiet.

The meta rule `phish_then_new_signin` correlates the verdict: a suspicious mail followed within 24 h by a successful
sign-in from an IP the user had never used before it. It stays silent without prior history (nothing to call "new").
URLs are defanged (`hxxp://198[.]51[.]100[.]200/login`) in the IOC list.

## Cases and shift handover

`--save` records the triage in a local SQLite case DB (`$HUNTERSCOPE_DB` or `~/.hunterscope/cases.db`, `--db` to
override). The same target (`jkowalski`, `jkowalski@contoso.com` and `CONTOSO\jkowalski` are one identity) keeps one
open case: re-triage updates its score and adds only findings it has not seen (content fingerprints), so running it
every hour does not duplicate anything.

```bash
hunterscope triage -i $S -u jkowalski --save
hunterscope case list                                   # open cases (--all for closed)
hunterscope case note 1 "Password reset forced, waiting for callback"
hunterscope case status 1 escalated_l2 -n "Inbox rule + OAuth consent confirmed, needs purge"
hunterscope case status 2 closed_fp  -n "Business trip WAW->LHR, 3 typos then success"
hunterscope case show 1                                 # findings + full audit log
hunterscope shift-summary --hours 12                    # rich tables in a terminal, Markdown when piped / -o
hunterscope shift-summary --redact -o handover.md       # safe to paste into a ticket
```

Rules that keep the handover trustworthy:
- Statuses: `new`, `in_progress`, `escalated_l2`, `escalated_l3`, `closed_fp`, `closed_tp`.
- **Closures and escalations require `--note`**: the next shift must be able to read *why*.
- **Closed cases are immutable.** A new triage of the same target opens a fresh case instead of silently reopening.
- Every note and status change is an append-only log entry with author and UTC time.
- Handover sections: unresolved (sorted by risk, `STALE` after 24 h without any touch), escalated (all still open,
  flagged if escalated this shift), and closed FP / TP from this shift with their reasons.

The case DB holds **real, un-redacted data**; it is git-ignored, single-writer and meant for a local disk, not a
network share. Redaction happens on output (`--redact`), never in storage.

## Explaining what you see (`explain`)

For the log line you do not understand. Two modes:

```bash
hunterscope explain 4688 certutil.exe 50126 T1003.001      # look terms up
hunterscope explain sysmon:10                              # prefix narrows a bare number
hunterscope explain -i $S -u jkowalski -t 7d               # explain a whole dossier
hunterscope explain -i $S -u jkowalski --redact -o ex.md   # target pseudonymized
```

A term resolves against: Windows event ids, Sysmon event ids, Entra ID error codes (`AADSTS50126` also works),
M365 audit operations, process names (a full path is fine, `.exe` optional), ATT&CK ids and HunterScope rule ids.
A bare number can be several of those at once; every match is shown. Prefixes: `event:` `sysmon:` `entra:`
`proc:` `ual:` `tech:` `rule:`.

Every entry has the same shape: **what it is, the risk, what normal looks like, what to check next, source**.
It is context for a decision, not a verdict: whether this occurrence is malicious depends on who, from where, and
what came before and after.

Dossier mode explains each rule that fired (once, even if it fired several times) with its ATT&CK techniques, then
the kinds of events in the window, those that are evidence of a finding first. Routine noise (a successful sign-in)
is hidden. Event kinds that the base does not describe are listed under **Bez wyjaśnienia**, so "unremarkable" is
never confused with "not covered". Unknown process names are not listed there (nearly all processes are ordinary).

Design decisions:
- **Nothing is generated.** The base (`config/knowledge.yaml`) is written by hand. A term that is not in it is
  reported as unknown and the command exits 1; it is never guessed.
- **The base cannot silently fall behind the tool.** Tests fail if a rule, an ATT&CK technique used by a rule, an
  Entra code the parser names, or a Windows/Sysmon event the parser handles has no entry.
- **Your own knowledge.** `--kb my.yaml` is merged by key: add your internal tools and agents, or override a
  wording. An entry missing a required field is an error, not a blank section.
- Text is Polish. Source links point to Microsoft, MITRE ATT&CK and LOLBAS pages. The entries were written from
  general knowledge of those sources and have **not** been checked line by line against the pages, and the links
  have not been machine-verified for reachability. Treat a wrong statement or a dead link as a bug; verify a
  security-relevant claim at the source before acting on it.

### Asking an LLM (`--llm`)

For a log line the base does not cover. **Off by default; nothing leaves your machine without `--llm`.**

```bash
pip install -e ".[llm]"                          # the anthropic package; not needed otherwise
export ANTHROPIC_API_KEY=...                     # or: ant auth login

hunterscope explain --log line.txt --llm --dry-run --redactor-config my.yaml   # 1. look at the payload
hunterscope explain --log line.txt --llm --redactor-config my.yaml             # 2. send it
hunterscope explain SomeVendorAlert --llm --redactor-config my.yaml            # unknown terms only
hunterscope explain -i $S -u jkowalski --llm --redactor-config my.yaml         # dossier: uncovered kinds only
```

Three modes use it. `--log FILE` (or `-` for stdin) takes raw text: the curated base always answers first for the
terms it recognises in it (`EventID=4688`, `AADSTS50126`, `T1003.001`, `certutil.exe`, an M365 operation), and the
model adds an explanation of the whole line. With terms, **only the ones the base does not know** go to the model.
On a dossier, at most five uncovered kinds of event go, **as ids only** ("Zdarzenie Windows 9999"), never raw events.

What protects the data:
- **Strict pseudonymization first.** Stricter than the offline default: public IPs and external addresses are
  masked too (the default keeps them as IOCs, but the model gains nothing from them and your egress IP is public).
  `--mask-user "Jan Kowalski"` and `--mask-host ws-jan` (repeatable) cover what the redactor cannot find by itself:
  free-text names and unknown short hostnames.
- **No default config.** The packaged redactor config only knows the fictional `contoso.com`, so `--llm` refuses to
  run without `--redactor-config FILE`, unless you pass `--allow-default-redaction` and accept that your own domain
  and usernames would pass through.
- **`--dry-run`** prints the exact system prompt and message and sends nothing. Use it on a new kind of log.
- **The log is untrusted.** It is fenced, a closing tag inside it cannot end the fence, and the system prompt says
  to treat it as data and to flag any instruction found in it.
- **Size.** More than 20 000 characters after redaction is refused, never silently truncated.
- **The answer is labelled** "generated by a model (unverified)" with the model name and the number of characters
  sent, and the curated entries that matched are shown next to it so the two can be compared. In JSON it carries
  `"verified": false`. It never produces a verdict: it lists what points each way and what to check.

Model and cost: the default is `claude-opus-5-5`; `--model claude-sonnet-5-5` (or `HUNTERSCOPE_LLM_MODEL`) is the
cheaper choice. A request is roughly 1-3 thousand input tokens plus the answer and its reasoning, so on the order of
a few cents at list prices. That figure is an estimate, not measured. For models that support it the request enables
the API's server-side refusal fallback; a refusal that still happens is reported with its category and exit code 3.
Exit codes: 3 means the LLM step failed (no credentials, rate limit, network, refusal); nothing partial is printed.

Limits: pseudonymization is regex based and says so ([Redaction](#redaction)); read the `--dry-run` output of any
new log format. The model can still be wrong, and explaining credential-theft tooling can trigger the provider's
safety filters. **This layer has not been run against the live API**: its request shape follows the SDK and the
provider's documentation and is covered by tests with a stubbed client, so expect to adjust it on first real use.

## Measured coverage

[`coverage.md`](coverage.md) is generated by running the rules against public, labelled datasets
([OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), 98 Windows datasets / ~752k events with
per-dataset ATT&CK labels; [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), labelled by
tactic only).

**Method.** Datasets are split 50/50 by a fixed hash into *dev* and *holdout*. Rules are designed from dev
telemetry only; holdout is read only through the report. The split was fixed after the first all-data report had
been read, so holdout is held out from rule design, not blind.

| Step | Dev (52 datasets) | Holdout (46) |
|---|---|---|
| Baseline, command-line rules only (in-scope datasets hit) | 3 / 10 | 1 / 7 |
| + `lsass_access` (Sysmon 10, designed on dev) | 5 / 10 | 3 / 7 |

Read the counts, not the percentages: the 95% intervals are 24-76% (dev) and 16-75% (holdout), because only 17
datasets carry a technique we have a rule for. What the numbers do support: the rule's two newly detected holdout
datasets are both Mimikatz variants it was never tuned on, and the T1003.001 row is 5/5 (3 dev, 2 holdout).

**Cost, not hidden.** `lsass_access` produced 10 findings: 5 on dev (1 without a matching label) and 5 on holdout
(3 without one). "No matching label" is not automatically a false positive (the labs run ancillary tooling), but
those three holdout findings were deliberately **not** inspected so the holdout stays clean. No benign baseline
exists in these datasets, so precision is not measured. Looking at them would turn holdout into dev; do that only
when the rule design is frozen.

Other honest limits:
- HunterScope is identity/phishing triage with a thin Windows layer, not an EDR. Most labelled techniques (WMI,
  injection, scheduled tasks, SMB/RDP lateral movement) have no rule; [`coverage.md`](coverage.md) lists every one.
- `lsass_access` needs Sysmon EventID 10 for lsass, which many production Sysmon configs filter out for volume.
  The allowlist in `rules.yaml` is a starting point to tune per environment, not a universal one.
- The cloud rules (Entra ID, M365, phishing) have no public labelled dataset here; they are covered by synthetic
  scenarios with documented outcomes.

Reproduce (needs `git`, ~260 MB; datasets go to git-ignored `data/external/`, never redistributed):

```bash
python scripts/fetch_datasets.py
pip install -e ".[bench]"
hunterscope coverage --otrf data/external/security-datasets --evtx data/external/evtx-attack-samples \
  --ablate lsass_access -o docs/coverage.md
```

## Score

Not a bare sum. First hit of a rule counts fully, repeats count 25%, one rule is capped at 2x its weight, and
activity across several ATT&CK tactics adds a bonus. The dossier lists every contribution, so an analyst can
see *why* a user has 73/100.

## Redaction

Single-pass, deterministic pseudonyms (`USER_A`, `INTERNAL_IP_1`, `HOST_2`); the same entity always gets the same
label, so the story stays readable. PESEL is matched only when the checksum is valid. With `--key-env VAR`
labels become HMAC-SHA256 tags: stable across runs and not reversible by brute-forcing small spaces (IPv4, PESEL).
`--mapping-out` writes label -> original and **contains the sensitive data**; keep it out of tickets.

Link URLs are kept as IOCs (like public IPs), but external *addresses* are masked.
Known limits: free-text names ("Jan Kowalski") are not detected; unknown short hostnames are not detected
(FQDNs are); public IPs are kept by default because they are IOCs, set `keep_public_ips: false`
(`--redactor-config`) before sharing outside the SOC. Your company's egress IP is public too.

## Data

`data/samples/` is synthetic and labelled as such. Do not commit real logs, and do not build this against
employer data.

## Roadmap / not done

- [x] `.eml` phishing triage (SPF/DKIM/DMARC, defanged URLs, attachment hashes) feeding the same dossier
- [ ] URL reputation / sandbox enrichment (optional, off by default; offline mode must keep working)
- [x] SQLite case store + `--shift-summary` handover (statuses, notes, open anomalies; md + terminal)
- [x] ATT&CK coverage measured against public datasets ([`coverage.md`](coverage.md))
- [ ] Sigma rules via pySigma for stateless patterns, evaluated on a held-out split of the same datasets
- [x] Sysmon 10 (ProcessAccess to lsass): closed the largest measured gap (T1003.001), measured with a holdout
- [x] Standalone HTML report (dossier and handover)
- [ ] Live OpenSearch client (last, only after everything works offline)
