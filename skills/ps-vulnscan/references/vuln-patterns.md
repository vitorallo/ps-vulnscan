# Vulnerability patterns for source review

Concrete code shapes to search for, per class, with the framework and ORM
variants that matter. Use them to locate **candidates**; a candidate becomes a
finding only after you open the file and confirm the check is genuinely absent.
Replace `<path>` with the subtree you are reviewing.

> Some patterns bracket a single character (e.g. `[H]`, `[e]`) — the classic
> `grep '[p]attern'` idiom. They match the real token normally; the brackets
> keep the raw sink name out of naive content scanners.

The highest-yield class in modern apps is **broken access control** (IDOR/BOLA
plus missing function-level authorization). Spend your review time there first —
it is also the class no rule pack can decide for you, because it depends on the
ownership model in `security/MODEL.md`.

---

## IDOR / BOLA — object access without an ownership check (CWE-639)

A handler loads or mutates an object using an id from the request, with no
`WHERE owner = session.user` (or tenant) constraint.

**Vulnerable shape:**
```js
// Express + Prisma — no ownership scoping
const inv = await prisma.invoice.findUnique({ where: { id: req.params.id } });
res.json(inv);                       // any user reads any invoice
```
```python
# Django — fetches by pk, ignores request.user
obj = Document.objects.get(pk=request.GET["id"])
```
```java
// Spring — repository by id, no owner check
@GetMapping("/api/orders/{id}")
public Order get(@PathVariable Long id){ return orderRepo.findById(id).get(); }
```

**Safe shape** — ownership is in the query, not just the UI:
```js
const inv = await prisma.invoice.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });
```

**Find it:**
```bash
grep -rnE "findUnique|findByPk|findById|getById|\.get\(pk=|objects\.get\(|findOne\(" <path>
grep -rnE "where:\s*\{\s*id" <path>          # JS/TS object-id queries
grep -rnE "@PathVariable|req\.params|request\.(GET|POST|args)\[" <path>
```
For each hit: does the same query, or an earlier guard, constrain by the session
user or tenant? If not → IDOR candidate. Record it against the route row in
`MODEL.md`.

---

## Missing function-level authorization (CWE-862)

```bash
grep -rnE "admin|internal|/users/|/roles|impersonate|/settings|export|delete" <path> | grep -iE "route|get|post|put|delete|mapping"
# then check each for a guard:
grep -rnE "requireAuth|isAdmin|hasRole|@PreAuthorize|@RolesAllowed|@login_required|before_action|permission_required|ensureAdmin" <path>
```
A privileged handler in the first list whose file or method lacks a guard from
the second is a candidate. **Confirm the guard isn't applied globally upstream**
(router-level middleware, a filter chain, a base controller) before flagging —
this is the most common false positive in the class.

---

## Mass assignment / over-posting (CWE-915)

Whole request body bound to a model, so the attacker sets fields they shouldn't
(`role`, `isAdmin`, `balance`, `ownerId`, `verified`).

```js
await User.update(req.body, { where:{ id:req.user.id }});   // role/isAdmin land here
const u = new User({ ...req.body });
```
```ruby
User.update(params[:user])         # without strong params
```
```java
@ModelAttribute User u             // binds all fields incl. role
```

```bash
grep -rnE "\.\.\.req\.body|req\.body\)|new \w+\(req\.body|update\(req\.body|\(\*\*request|@ModelAttribute|params\[:" <path>
```
Check for an explicit allowlist: named fields, a DTO, strong params, or a
Pydantic model with fixed fields.

---

## SQL injection (CWE-89)

```bash
grep -rnE "query\(\s*[\"'\`].*\+|execute\(\s*f[\"']|\.raw\(|createQuery\(\s*\"|String\.format.*SELECT|sequelize\.query\(" <path>
```
Concatenation or interpolation of request input into a query string.
Parameterized queries and ORM query builders are safe — dismiss those.

---

## Command injection (CWE-78) & code eval (CWE-94)

```bash
grep -rnE "exec\(|execSync|spawn\(.*shell|child_process|os\.system|subprocess.*shell=True|Runtime\.getRuntime\(\)\.exec|eval\(|new\s+Function\(|pickl[e]\.loads|yaml\.load\(" <path>
```

---

## SSRF (CWE-918)

```bash
grep -rnE "axios\.(get|post)\(|fetch\(|requests\.(get|post)\(|http\.get\(|URL\(|HttpClient|urlopen\(" <path>
```
Trace the URL argument back to request input; check for scheme/host allowlisting
and blocking of internal ranges and the cloud metadata endpoint
(`169.254.169.254`).

---

## Insecure deserialization (CWE-502) & XXE (CWE-611)

```bash
grep -rnE "pickl[e]\.loads|yaml\.load\(|ObjectInputStream|readObject|Marshal\.load|unserialize\(|node-serialize|XMLReader|DocumentBuilder|SAXParser" <path>
```
For XXE, check that external entities and DOCTYPE are disabled on the parser.

---

## Session, cookies & JWT (CWE-384 / CWE-614 / CWE-347)

```bash
grep -rnE "jwt\.(verify|decode)|algorithms?\s*[:=]|verify\s*[:=]\s*false|cookie\(|session\(|set_cookie|SameSite|HttpOnly|Secure" <path>
```
Check: signature verified with a fixed algorithm (no `none`, no HS↔RS
confusion); decode-without-verify never used for auth; cookies `HttpOnly` +
`Secure` + `SameSite`; session id rotated on login; logout invalidates
server-side.

---

## CSRF (CWE-352) & open redirect (CWE-601)

```bash
grep -rnE "csrf|csurf|SameSite|redirect\(|res\.redirect|sendRedirect|location\s*=" <path>
```
State-changing routes need CSRF protection unless they are token-auth APIs.
Redirects to a request-supplied destination need a host allowlist.

---

## XSS (CWE-79)

```bash
grep -rnE "dangerouslySetInner[H]TML|innerHTML|v-html|\|\s*safe|mark_safe|render_template_string|res\.send\(.*req\.|\$\{.*req\." <path>
```
Check output encoding and template auto-escaping; flag raw HTML sinks fed by
request data.

---

## File upload (CWE-434) & path traversal (CWE-22)

```bash
grep -rnE "multer|upload|MultipartFile|request\.files|path\.join\(.*req|\.\./|sendFile\(|FileInputStream\(.*req|os\.path\.join\(.*request" <path>
```
Check server-side type and size enforcement, randomized storage names, storage
outside the web root, and traversal-safe path handling.

---

## Hardcoded secrets (CWE-798)

```bash
grep -rnE "(api[_-]?key|secret|passwd|password|token|private[_-]?key)\s*[:=]\s*[\"'][A-Za-z0-9/+_-]{16,}" <path>
grep -rnE "BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}" <path>
```
A live credential committed to the repo is a **real finding**, not hygiene —
report it. Check whether it is still valid and whether git history retains it
(`git log -p -S '<fragment>'`); a rotated key is still a finding about the
process. Never paste the full secret into the report — quote a prefix.

---

## False positives — dismiss with a named reason

When a candidate turns out safe, record which of these applies, with the
`file:line` of the evidence. A dismissal without a reason is just an unexamined
finding.

- Ownership or tenant check exists in an upstream middleware, guard, or filter
- Query is parameterized or uses the ORM builder, not string concatenation
- The framework auto-escapes this output context
- Input is server-derived (session, JWT claim, config), not user-controlled
- Route is not registered, is dev-only, or sits behind a globally applied guard
- Strong params / DTO / Pydantic model allowlists the fields (not mass assignment)
- The value is validated against an allowlist before reaching the sink

## Not headline findings

Note these, don't lead with them — they inflate a report and bury the real bugs:

- **Dependency CVEs with no demonstrated reachable call path** → appendix, as a
  list. If you *can* trace the call path, it stops being an appendix item and
  becomes a finding.
- **Missing security headers with no concrete attack** → appendix. A missing
  `X-Frame-Options` on a page with a state-changing action you can frame is a
  finding; a missing header on a JSON API is a note.
- **Self-XSS**, and theoretical issues on routes that are not registered.
