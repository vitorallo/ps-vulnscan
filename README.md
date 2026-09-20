# ps-vulnscan

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin by
[PEACH STUDIO](https://www.peachstudio.be). Scan a codebase for vulnerabilities
against secure-coding rules chosen for the stack it actually uses.

```
stack ID → app/auth model → rule packs [you confirm] → scan & confirm → one report
```

| Skill | What it does |
|-------|-------------|
| `ps-vulnscan` | Detects the project's languages, frameworks and AI surface; models its identities, roles, tenancy and authorization into `security/MODEL.md`; proposes the matching rule packs and downloads them from [claude-secure-coding-rules](https://github.com/TikiTribe/claude-secure-coding-rules); reviews the source against those rules; writes one consolidated report with CVSS per finding. |

Coverage leads with **broken access control** — IDOR/BOLA, missing
function-level authorization, cross-tenant leaks — then injection, SSRF,
deserialization, session and JWT flaws, mass assignment, CSRF and open redirect,
upload and path traversal, committed secrets, and the rest of the OWASP Top 10
2025.

## What it doesn't do

No MCP server, no external scanner service, no cloud model, no exploitation and
no PoC development. It reads source and writes a report. The only network call
is the one-time rules clone — plus the semgrep registry, if you choose semgrep.

## Install

```bash
/plugin marketplace add vitorallo/peach-studio-marketplace
/plugin install ps-vulnscan@peach-studio
```

Then, in the project you want to scan:

> scan this project for vulnerabilities

## How it works

**1. Stack identification.** Manifests are read rather than guessed at —
`package.json`, `pyproject.toml`, `go.mod`, `pom.xml`, `Gemfile`, `Cargo.toml`,
Dockerfiles, CI workflows, Terraform. The AI packs are chosen from actual
dependencies (`openai`, `langchain`, `mcp`, a vector store client), not from
vibes.

**2. The app model.** Principals and roles, where roles are assigned versus
checked, the tenancy key and whether it comes from the session or the request,
ownership fields per model, a routes × authorization table, and the sensitive
workflows. This is what makes the scan find missing authorization instead of
just dangerous-looking function calls — no rule file knows who is supposed to
own what in your app.

**3. Rule packs — the one checkpoint.** You are shown the proposed pack list and
the engine choice, and nothing is downloaded until you approve. Packs land in
`security/rules/` with a `.manifest` recording the upstream commit.

They are deliberately **not** installed under `.claude/` and carry no `paths:`
frontmatter, so they never auto-load into your sessions — the scan opens the
ones it needs. (If you want rules loaded into every coding session instead,
that's what [`ps-spec`](https://github.com/vitorallo/ps-spec) does.)

**4. Scan and confirm.** Rule-driven grep and source review by default, or
semgrep if you prefer it and have it installed. Either way, every candidate is
read in the source before it reaches the report: the route is registered, the
value is genuinely attacker-controlled, no upstream guard already handles it.
Candidates that don't survive that are dismissed against a named reason.

**5. Report.** One consolidated markdown file — severity and CVSS v3.1 vector,
CWE, affected handler, a reachability paragraph, quantified impact, remediation
code. Dependency advisories with no reachable call path and header hygiene go to
appendices rather than padding the finding count.

## Output

```
security/
├── .gitignore                 "*" — scan output self-ignores
├── MODEL.md                   the app and authorization model
├── rules/                     the downloaded packs + .manifest
├── semgrep.json               only if you chose semgrep
└── findings/<target>-security-report.md
```

## Rule packs

From [TikiTribe/claude-secure-coding-rules](https://github.com/TikiTribe/claude-secure-coding-rules)
(MIT): OWASP Top 10 2025, AI/agent/MCP/RAG/graph security, 12 languages, backend
and frontend frameworks, containers, CI/CD, IaC, and ~25 RAG tool packs.

```bash
bash skills/ps-vulnscan/scripts/ps-vulnscan-rules.sh --list                 # the catalogue, with sizes
bash skills/ps-vulnscan/scripts/ps-vulnscan-rules.sh --packs core,python,fastapi
bash skills/ps-vulnscan/scripts/ps-vulnscan-rules.sh --update               # re-pull, reinstall what .manifest lists
bash skills/ps-vulnscan/scripts/ps-vulnscan-rules.sh --src ~/src/claude-secure-coding-rules --packs core
```

The repo is cloned once into `~/.cache/ps-vulnscan/` and reused, so repeat scans
are reproducible against a known commit; `--update` is the explicit "give me
current rules" switch. `PS_VULNSCAN_RULES_SRC` overrides the source.

## Optional: semgrep

semgrep OSS can stand in for the grep pass on large codebases.

```bash
brew install semgrep        # or: pipx install semgrep
```

Its `p/…` rule packs are fetched from the semgrep registry over the network. No
login is needed and **your code is not uploaded** — semgrep runs locally, only
the rules come down. The default grep path is fully offline once the rule packs
are cloned. The skill never runs `semgrep login` or `semgrep ci`.

semgrep is a candidate generator, not a source of findings: its hits get the
same reachability review as everything else, because it cannot see the
middleware that makes half of them false positives.

## Scope and ethics

Scan code you own or are authorized to review. Nothing is executed — no
requests, no exploitation, no PoCs — so findings are code evidence, and the
report says so. Runtime and deployment issues are out of reach by construction,
and the scope section states that plainly.

## Related

- [`ps-spec`](https://github.com/vitorallo/ps-spec) — epic-driven development on
  OpenSpec; installs the same rule packs into `.claude/rules/security/` so they
  guide code as it's written. Prevention; ps-vulnscan is detection.
- [`peach-vulnhunt`](https://github.com/vitorallo/peach-vulnhunt) — the deeper
  hunt: foil-powered scanning, chained attack scenarios, PoC development and
  coordinated disclosure.

## Licence

MIT. Rule packs are MIT, from TikiTribe/claude-secure-coding-rules.
