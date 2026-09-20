# semgrep — optional scan engine

semgrep OSS is a pattern-based static analyser. It is faster and more systematic
than grep at finding known sink shapes across a large codebase, and useless at
the thing that matters most here — deciding whether a missing ownership check is
a bug in *this* app. Treat it as a candidate generator that feeds the same
triage, never as the source of findings.

## Install

```bash
brew install semgrep                 # macOS
pipx install semgrep                 # any platform, isolated
python3 -m pip install semgrep       # any platform, into the current env
```

Check it: `semgrep --version`. If it isn't installed and the user doesn't want
to install it, the rule-driven grep path covers the same classes — offer that
rather than blocking the scan.

## Running it

```bash
semgrep scan --config p/owasp-top-ten --config p/security-audit \
  --json --output security/semgrep.json \
  --exclude node_modules --exclude vendor --exclude dist --exclude build .
```

Useful additions: `--config p/secrets` for credential detection,
`--config p/<language>` (e.g. `p/python`, `p/javascript`) for language packs,
`--severity ERROR` to cut the long tail on a first pass.

**Network note, say this to the user before running it:** `p/...` configs are
rule packs fetched from the semgrep registry over the network. No login is
required and **your code is not uploaded** — semgrep runs locally on your
machine; only the rules come down. If that fetch is unacceptable, either point
`--config` at a local rules directory or use the grep path, which is fully
offline once the rule packs are cloned.

Avoid `semgrep login` / `semgrep ci` — those are the managed-platform flows and
do send findings to Semgrep AppSec Platform. This skill has no business doing
that.

## Folding the output into the scan

semgrep's JSON gives you `check_id`, `path`, `start.line`, `extra.message`,
`extra.severity`, and `extra.metadata` (CWE, OWASP category, confidence). Use it
to prioritise, then do the work:

1. Group hits by `check_id` — a rule firing 200 times is one systemic problem,
   not 200 findings. Report it once, with a representative `file:line`, the
   count, and one systemic remediation.
2. **Open and read each hit you intend to report.** semgrep does not know about
   upstream middleware, so its access-control and taint results need the same
   reachability check as a grep hit: is the value genuinely attacker-controlled,
   is the path registered, is there a guard it can't see?
3. Dismiss with a reason from the false-positive list in `vuln-patterns.md`.
   semgrep's own `nosemgrep` comments in the codebase are a claim by a previous
   developer, not evidence — check them rather than trusting them.
4. Cross-check against the downloaded rule packs: where semgrep and a pack rule
   agree, you have a strong finding; where a pack rule has no semgrep
   counterpart (most access-control and business-logic rules), that is exactly
   the area to review by hand against `MODEL.md`.

Keep `security/semgrep.json` as an artifact and cite it in the report's scope
section, including the configs used — it is part of how the scan was performed.
Do not paste raw semgrep output into the report as findings.
