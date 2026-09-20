---
name: ps-vulnscan
description: Scan a codebase for real, exploitable vulnerabilities using secure-coding rule packs matched to its own stack. Detects which technologies the project uses, proposes the matching rule packs, downloads them from claude-secure-coding-rules, models the app's identities, roles, tenancy and authorization, then reviews the source against those rules and writes one consolidated report with CVSS per finding. Covers broken access control and IDOR/BOLA first, then injection, SSRF, deserialization, session and auth flaws, secrets, and the rest of the OWASP Top 10. Rule-driven grep-and-read by default, optional semgrep. Use this skill whenever the user asks to scan, audit, or security-review a codebase or project, asks whether their code is secure or has security issues or vulnerabilities, asks about OWASP Top 10 / IDOR / injection / access control in their own code, or says "ps-vulnscan" or "vulnscan" — even if they don't use the word "scan". No MCP server, no external scanner service, no exploitation.
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, AskUserQuestion, WebSearch
---

# ps-vulnscan

Scan the current project for vulnerabilities, against rules chosen for the stack
it actually uses.

```
Stage 1 stack ID → Stage 2 MODEL.md → Stage 3 rules + engine [checkpoint] → Stage 4 scan & confirm → Stage 5 report
```

Two ideas carry this skill. First, **generic rules find generic bugs**: the packs
that matter are the ones written for this project's languages and frameworks, so
detect the stack before fetching anything. Second, **a pattern match is not a
finding**: the highest-value bugs in modern applications are missing
authorization checks, which no rule file can recognise without knowing who owns
what in this app. That is why the model comes before the scan and why every
candidate gets read in the source before it reaches the report.

Everything runs locally. The only network call is the one-time rules clone (plus
the semgrep registry if the user picks semgrep).

## Output layout

Everything the scan produces lives under `security/` in the project:

```
security/
├── .gitignore                 containing "*" — scan output self-ignores
├── MODEL.md                   the app and authorization model (Stage 2)
├── rules/                     downloaded rule packs + .manifest (Stage 3)
├── semgrep.json               only if semgrep was the chosen engine
└── findings/<target>-security-report.md    the deliverable (Stage 5)
```

Create `security/.gitignore` with a single `*` in Stage 1, before writing
anything else there. A scan of someone's repository should not turn into a
commit they didn't ask for, and a half-finished report in a diff is worse than
no report.

## Stage 1 — Identify the stack

Read the manifests rather than guessing from file extensions: `package.json`,
`pyproject.toml` / `requirements.txt`, `go.mod`, `pom.xml` / `build.gradle`,
`Gemfile`, `composer.json`, `Cargo.toml`, `Dockerfile*` / `compose*.yml`,
`.github/workflows/`, `.gitlab-ci.yml`, `*.tf`.

Produce a short summary of:

- **Languages and frameworks**, with the web framework named explicitly.
- **Data layer** — ORM or query builder, and whether raw SQL appears anywhere.
- **Auth and session** libraries — JWT, sessions, an identity provider, an RBAC
  or policy library.
- **AI surface**, from dependencies not vibes: an LLM client (`openai`,
  `anthropic`), an agent framework, `@modelcontextprotocol/sdk` or `mcp`, a
  vector store client, a graph driver. These decide whether the specialised
  `_core` packs are worth their size.
- **Entry points** — route and controller files, GraphQL schemas and resolvers,
  Next.js route handlers and server actions, webhook receivers, queue consumers,
  scheduled jobs. These are where untrusted input arrives.
- **Where authorization lives** — middleware, guards, decorators
  (`@PreAuthorize`, `@login_required`, `before_action`), policy modules. Note
  whether it looks centralized or ad-hoc; ad-hoc is where the gaps will be.

Exclude `node_modules`, `vendor`, `dist`, `build`, `.venv`, generated code,
fixtures and tests from the review surface — but read the tests when a rule's
applicability is unclear, because they document intended behaviour better than
comments do.

Tell the user what you found in a few lines before moving on.

## Stage 2 — Model the app

Follow `references/app-model.md` and write `security/MODEL.md`. The core of it:
the principals and how roles are assigned versus checked; the tenancy key and
whether it comes from the session (good) or the request (dangerous); the
ownership field on each model; a routes × authorization table; and the sensitive
workflows — login, password reset, email change, MFA, invitations, checkout,
transfers, upload and download, deletion, admin and impersonation.

This is the stage that decides whether the scan finds real bugs or just sink
shapes, so give it real effort — but keep it proportionate: on a small codebase
it is a page, not an afternoon. Leave a cell blank when you don't know. An
invented ownership field produces invented findings, and a report built on one
is worse than no report.

Summarise the model for the user and note where it is uncertain. Don't stop for
approval — the scan will confirm or correct it, and corrections belong in
`MODEL.md` as you make them.

## Stage 3 — Rules and engine (the checkpoint)

This is the one point where the run waits for the user, because it downloads
files into their project and may make a network call they didn't expect.

Infer the pack list from Stage 1 using the mapping in `references/rule-packs.md`:
always `core` (OWASP Top 10 2025), one pack per language and framework in use,
and `ai-security` / `agent-security` / `mcp-security` / `rag-security` /
`graph-database-security` **only** when the code really does that thing. Run
`bash <this-skill-dir>/scripts/ps-vulnscan-rules.sh --list` if you need the live
catalogue.

Then check for the optional engine: `command -v semgrep`.

Ask both questions in **one** `AskUserQuestion` call:

1. **Rule packs** — the proposed list, with approve / edit the list / skip as
   options. Show the list itself in the question so the user can see what they
   are approving.
2. **Engine** — rule-driven grep and source review (the default, fully offline),
   or semgrep. Offer semgrep as an option only when it is installed; when it
   isn't, say so in the option description along with `brew install semgrep` or
   `pipx install semgrep`, so the user can choose it for a future run. Whenever
   semgrep is on the table, state plainly that its `p/…` rule packs are fetched
   from the semgrep registry over the network, no login, and that **no code
   leaves the machine**.

Then download:

```bash
bash <this-skill-dir>/scripts/ps-vulnscan-rules.sh --packs core,typescript,express,react
```

Packs land in `security/rules/` with a `.manifest` recording the source commit.
They are deliberately not installed under `.claude/` and carry no `paths:`
frontmatter: they are a checklist you open on purpose in Stage 4, not context
injected into every future session in the user's project.

The clone happens once and later runs reuse it, so a scan is reproducible and
the manifest commit describes exactly what the code was judged against. Pass
`--update` when the user wants current rules.

If the user skips the packs, the scan still runs on `references/vuln-patterns.md`
alone — say that the coverage is narrower and carry on.

## Stage 4 — Scan and confirm

Work one technology at a time: read the pack for it, then review the code it
covers. `references/rule-packs.md` explains how to turn a pack's
`### Rule:` blocks into checks — `When` tells you whether the rule is in scope
here at all, `Don't` gives you the shape to search for, `Do` becomes the
remediation, `Refs` gives the CWE.

Three sources of candidates, in order of yield:

1. **The routes × authorization table in `MODEL.md`**, walked row by row. For
   every request that carries an id, does an ownership or tenant check run
   *before* the object is used, and is it in the query rather than the UI? This
   finds the bugs nothing else will.
2. **The grep recipes in `references/vuln-patterns.md`**, per class.
3. **The rule packs' own `Don't` shapes**, translated to this codebase's idiom.

Plus semgrep output when that engine was chosen — see `references/semgrep.md`
for the invocation and for how to fold its results in rather than pasting them.

**Then open the file and read it.** A candidate becomes a finding only when you
can state, from the source, how untrusted input reaches the dangerous operation:
the route is registered, the value is genuinely attacker-controlled, and no
upstream guard or downstream validation already handles it. Trace one more hop
before you commit either way — the most common mistake in this kind of review is
reporting a handler whose router applied a guard two files up.

When a candidate is safe, dismiss it against a named reason from the
false-positive list in `references/vuln-patterns.md`, with the `file:line` that
proves it. A dismissal without a reason is just an unexamined finding.

Apply the noise filter as you go, and keep the proportions honest:

- A **committed secret or credential is a real finding** — check whether git
  history still carries it, and quote only a prefix.
- **Dependency advisories with no reachable call path** go to Appendix A. If you
  can trace the path, it becomes a finding instead.
- **Missing headers, permissive CORS, verbose errors** with no concrete attack
  go to Appendix B.
- Self-XSS and routes that are not registered are not findings.

On a large codebase, don't try to hand-verify everything — a rule firing two
hundred times is one systemic problem. Report it once with a representative
`file:line`, the count, how many you actually verified, and one systemic fix.
Say which areas you did not get to; silence reads as "reviewed and clean".

## Stage 5 — Report

Write one consolidated `security/findings/<target>-security-report.md` following
`references/report-template.md` — never per-finding files.

Each finding carries severity plus a CVSS v3.1 vector, the CWE and category, the
affected endpoint and handler `file:line`, a description that names the missing
check rather than the bug class, the vulnerable code, a **reachability**
paragraph, quantified impact, and remediation as code the project could actually
adopt. Score CVSS from the code — for access-control bugs `PR`, `S` and `C`/`I`
are what move the number — and let the score drive the label rather than the
reverse.

Fill the scope and limitations section honestly: what was excluded, and that
nothing was executed, so runtime and deployment issues are out of reach by
construction.

Finish by telling the user where the report is, the headline count by severity,
and the one thing you would fix first.

## Guardrails

- **Authorized targets only.** Scan code the user owns or is authorized to
  review. If a repository's provenance is unclear, ask before scanning.
- **Nothing is executed.** This skill reads source; it does not run the
  application, send requests, or exploit anything. Findings are code evidence,
  and the report should never imply a vulnerability was demonstrated at runtime.
  If a finding truly needs dynamic proof, say so in the finding.
- **No exploit or PoC development.** Remediation code yes; working exploits no.
- **Don't inflate.** A clean area reported as clean is a useful result. Padding
  a report with hygiene notes dressed as findings destroys its credibility and
  buries the bugs that matter.
- **Say what you didn't cover.** Partial coverage stated plainly is fine;
  partial coverage left implicit is misleading.

## References

Read the one that matches the stage you're in:

- `references/app-model.md` — how to model identities, tenancy, ownership and
  workflows, plus the `MODEL.md` template (Stage 2).
- `references/rule-packs.md` — the pack catalogue, the stack → pack mapping, and
  how to read a pack as scan checks (Stages 3–4).
- `references/vuln-patterns.md` — per-class grep recipes, safe versus vulnerable
  shapes, the false-positive taxonomy, and the noise filter (Stage 4).
- `references/semgrep.md` — installing semgrep OSS, the exact invocation, the
  registry network note, and how to fold its output into triage (Stages 3–4).
- `references/report-template.md` — the consolidated report skeleton and how to
  score severity (Stage 5).
