# Report template

Write **one consolidated markdown report** to
`security/findings/<target>-security-report.md`. Do not split it into a separate
executive summary plus per-finding files — that duplicates content, and a reader
who has to open six files to understand one attack will not do it.

Number findings `[001]`, `[002]`, … in descending severity, so the document
reads top-down for someone who only gets through the first page.

Fill the header's tester and dates from the engagement, not from guesswork; if
you don't know who the tester is, leave the placeholder in rather than inventing
a name.

---

```markdown
# Security assessment: <target>

- **Target:** <app name / repo>
- **Scope:** <what was reviewed — subtrees, entry points, roles; and what was not>
- **Assessment date:** <YYYY-MM-DD>
- **Tester:** <tester name / organisation>
- **Method:** rule-driven source review + manual access-control analysis
- **Rule packs:** <packs> @ `<commit>` (see `security/rules/.manifest`)
- **Engine:** rule-driven grep + source review <, semgrep p/owasp-top-ten + p/security-audit>

## Executive summary

[2–4 sentences. The dominant risk theme in business terms — e.g. "broken
object-level authorization across the API allows any authenticated user to read
and modify other tenants' data." Then the headline numbers: how many findings at
each severity. If the codebase is in good shape, say that plainly; a report that
manufactures concern to look thorough is worse than a short one.]

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |

## Findings

### [001] <Short title> (<Severity>)

- **Severity:** <Critical/High/Medium/Low> — CVSS v3.1 <N.N> (`<AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_>`)
- **CWE:** CWE-NNN (<name>) · **Category:** <Broken Access Control / Auth & Session / Injection / Business Logic / …>
- **Affected:** `<METHOD> <path>` — handler `<file:line>`
- **Preconditions:** <none / any authenticated user / role X / tenant member>
- **Rule:** <pack> → "<rule name>" <, semgrep check_id>

**Description** — [the root cause in specific terms. Not "IDOR" but "the
`GET /api/invoices/:id` handler fetches by id with no ownership filter, so any
authenticated user can read any invoice." Name the check that is missing or
bypassable, and say where it should have been.]

**Affected code**
```<lang>
// <file:line>
<vulnerable code>   // ← why this is wrong
```

**Reachability** — [how untrusted input reaches this code: the route is
registered at `<file:line>`, no upstream guard applies because `<reason>`, the
value originates from `<request element>`. This is the paragraph that separates
a finding from a pattern match.]

**Impact** — [concrete, quantified. "Every invoice of every tenant — approximately
N records" beats "information disclosure".]

**Remediation**
```<lang>
// scope the query to the caller
const inv = await prisma.invoice.findFirst({ where: { id, ownerId: req.user.id } });
```
[Then the defence in depth: centralise authorization in a policy or middleware,
add a test asserting cross-user access returns 403.]

## Scope & limitations

[What was and was not reviewed, and why. Which subtrees were excluded
(dependencies, generated code, tests). Which classes the method cannot reach —
runtime configuration, deployed infrastructure, anything requiring a live
instance, since nothing was executed. If coverage of an area was partial, say so
here; a reader will assume "not mentioned" means "reviewed and clean" unless you
tell them otherwise.]

## Appendix A — dependency advisories

[Known-vulnerable dependencies for which **no reachable call path was
demonstrated**. Listed for patch planning, not as findings. Name the package,
version, advisory id, and say plainly that reachability was not established.]

## Appendix B — configuration & hardening notes

[Missing security headers, permissive CORS, verbose errors, cookie flags, and
similar hygiene items with no concrete attack demonstrated. Worth fixing, not
worth alarming anyone.]

## References

- App and authorization model: `security/MODEL.md`
- Rule packs used: `security/rules/` (`.manifest` records source and commit)
- <semgrep output: `security/semgrep.json`>
- OWASP Top 10 2025, and the CWE ids cited above
```

## Severity, briefly

Score CVSS v3.1 and let it drive the label rather than the other way round. For
access-control bugs the decisive metrics are **PR** (none > low > high — an
anonymous-reachable bug outranks one needing a login), **S** (scope changes when
a tenant boundary is crossed), and **C/I** (read versus read-and-write).

A finding whose CVSS you cannot justify from the code is a finding you have not
finished investigating. Either do the reachability work or move it to the
appendix and say it is unverified — never pad the count.
