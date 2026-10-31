# Sigma benchmark: protocol fixed before measuring

This file was committed **before** the Sigma engine was written and before any Sigma result existed. If a later
commit changes it, the change is visible in the history and is a reason to distrust the result that follows it.

## Question

HunterScope's own Windows rules detect 8 of 17 in-scope OTRF datasets (3 of 7 in the holdout). They were written
by one person, partly looking at the data. How much does a **third-party** rule set, written by other people who
never saw these datasets, add?

## Rule set (fixed)

- SigmaHQ/sigma at commit `05d1031f537e830b76da53bae2400c5814c89165` (2026-10-21), directory `rules/windows`
  (2,425 rules). Fetched by `scripts/fetch_datasets.py sigma`, never committed (Detection Rule License 1.1).
- Included: `status` in {stable, test, experimental} and `level` in {medium, high, critical}. Excluded before looking
  at any data: `low` and `informational` rules (they exist to hunt, not to alert, and would swamp a precision-blind
  benchmark with noise).
- Rules using an unsupported feature (see the engine) are **excluded and counted**, never silently dropped.
  The number supported out of the number eligible is reported.
- Only rules whose logsource maps to a telemetry type the datasets contain are evaluated: Sysmon events by
  EventID, Security 4688 for process creation, and `service: security|system|sysmon`. The mapping is in
  `src/hunterscope/sigma/logsource.py`.

## Split discipline

- Same dev / holdout split as the rest of the project (`SPLIT_SALT = 'hunterscope-split-v1'`).
- The Sigma rules themselves are not tuned by me, so they cannot overfit. What *can* go wrong is my engine and my
  field mapping. Those are debugged **on dev datasets only**.
- The holdout is read only through the final report. After that report is generated I change neither the rule
  filter nor the mapping. A needed change means a new split, stated as such.

## Metrics

- **A, comparable:** the 17 datasets that were "in scope" for HunterScope's own rules. Hit = at least one finding
  in the right ATT&CK family. Reported for HunterScope alone, Sigma alone, and the union.
- **B, broader:** all datasets labelled with a technique family that at least one loaded Sigma rule is tagged
  with (determined from rule tags only, without looking at telemetry).
- **Noise signal, not precision:** matches by rules whose ATT&CK families do not intersect the dataset's labels
  ("off-label"). The labs run ancillary tooling, so off-label is not automatically a false positive, and there
  is no benign baseline, so precision is **not** measured.

## What would count as a bad result (stated in advance)

- Union no better than HunterScope alone on the holdout in metric A.
- More than a handful of rules firing on most datasets (a sign of an engine bug, e.g. a wildcard matching everything).

## Amendment (written after the first result was seen)

The first run showed Sigma alone catching more datasets than HunterScope's rules, with the union equal to Sigma
alone. Because the family-level hit definition is generous (a T1003.001 finding credits a T1003.002 label), a
stricter exact-sub-technique table was added to the report as a robustness check. The headline tables, the rule
filter and the field mapping were not changed after seeing the result. Not done: restricting to high/critical rules,
or any per-rule tuning.
