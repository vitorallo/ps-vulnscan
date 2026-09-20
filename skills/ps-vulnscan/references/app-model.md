# Modeling the app before you scan

Rule packs and grep patterns find dangerous *shapes*. Access-control and logic
flaws are not a shape — they are the **absence of a check that should have been
there**, and nothing in a rule file knows which check this app owes you. A
`findUnique({ where: { id } })` is correct code in a public catalogue and a
critical data breach in a multi-tenant SaaS. The difference is the model.

So build the model first, write it to `security/MODEL.md`, and scan against it.
It is the hunting checklist, and it seeds the report's scope section.

## Step 1 — Identities, roles, and tenancy

- **Principal types:** anonymous, registered user, admin, tenant/org admin,
  support/impersonator, service account, API key, machine-to-machine?
- **Where are roles assigned?** Signup defaults, admin grants, invitation
  acceptance, SSO claims, JWT claims. Can a user influence their own role
  (mass assignment on `role`, a self-grant endpoint)?
- **Where are roles checked?** Centralized middleware/guard/policy, or ad-hoc
  per handler? Ad-hoc checking is where function-level authorization gaps hide,
  because "we check it everywhere" is never true everywhere.
- **Multi-tenancy:** is data partitioned by `orgId`/`accountId`/`tenantId`? Is
  that key derived from the **session** (good) or taken from the **request**
  (dangerous)? Every query that omits the tenant filter is a candidate
  cross-tenant leak.
- **Ownership key:** what field ties an object to its owner (`userId`,
  `ownerId`, `customerId`)? List the models that have one — and the ones that
  should have one and don't.

## Step 2 — Trust boundaries and object references

For every route, note where untrusted input crosses into a trusted action:

- Which **IDs** appear in the request (path `:id`, body fields, query params,
  headers, JWT claims)? Each one that selects or mutates an object is an IDOR
  candidate.
- Is the ID **validated for ownership/tenant before use**, and is that check in
  the **data query** (`WHERE id = ? AND owner = session.user`) rather than only
  in the UI or a client-side route guard?
- Which inputs are **trusted by mistake** — price, total, quantity, role,
  `isAdmin`, status, `userId` sent by the client and used without server-side
  recomputation?

## Step 3 — The sensitive workflows

For each multi-step flow, write down the intended sequence and the state guard
on each step. These are where the high-value bugs live:

### Authentication & session
Login: account enumeration (different error or timing for an unknown user),
missing lockout or rate limit (CWE-307). Session: is a new session ID issued on
login (else session fixation, CWE-384)? Cookie flags `HttpOnly`/`Secure`/
`SameSite` (CWE-614)? Does logout invalidate server-side? JWT: is the signature
actually verified, with a fixed algorithm (no `alg: none`, no HS/RS confusion,
CWE-347)? Are `role`/`userId` claims trusted without re-check? Is expiry
enforced?

### Account recovery — the highest-value target
**Password reset:** token entropy and expiry; is the token **bound to the user**,
or can you submit user A's token with user B's id? Is the link leaked via the
`Host` header or a referrer? Does reset invalidate existing sessions.
**Email/phone change:** does it require re-auth and confirmation to the *old*
address — can changing an email take over another account?
**MFA:** can enrollment or disable happen without the password? Can the second
factor be skipped by replaying the pre-MFA session or calling the post-login
endpoint directly?

### Invitations, roles & impersonation
Can an invite grant a higher role than the inviter holds? Can you accept an
invite addressed to someone else? Can support-impersonation be invoked by a
normal user?

### Commerce / value transfer
Checkout: are price, total, currency and discount recomputed server-side or
trusted from the client? Can "order complete" be reached without "payment
captured"? Negative quantities or amounts? Coupons and refunds: can the same one
be replayed (missing idempotency), or refunded for more than was paid?
Transfers: double-spend under concurrent requests (TOCTOU), or transfer from an
account you don't own (IDOR on `fromAccount`).

### Files & resources
Upload: type/extension/content-type enforced server-side (CWE-434)? Path
traversal in the stored filename (CWE-22)? Stored where it can execute?
Download: is the file id ownership-checked, or can anyone fetch `/files/123`?

### Account lifecycle & admin
Deletion or export of another user's account (IDOR). Admin-only routes reachable
by normal users (missing function-level authorization). Debug endpoints,
actuators, or GraphQL introspection exposed in production.

## Step 4 — Reading a workflow for flaws

You are reviewing source, not sending requests, so apply these **on paper**:
read the handler for step 3 and ask whether it re-derives the state that steps
1–2 were supposed to establish.

1. **Step skip** — does step 3's endpoint verify steps 1–2 happened, or does it
   trust that the client followed the flow? (Order completion without a captured
   payment; email verification without owning the token.)
2. **Step reorder** — does later state validate earlier state, or only its own
   input?
3. **Replay** — is the operation idempotent? A missing uniqueness or
   already-used check means double credit, double refund, reused coupon.
4. **Concurrency / TOCTOU** — is the check-then-act pair inside a transaction or
   a lock? A read-then-write on a balance or a one-per-user limit without one is
   a race.
5. **Parameter tampering** — which of price, quantity, role, `userId`,
   `isAdmin`, status, totals comes from the request and reaches persistence
   without being recomputed or allowlisted?
6. **Object enumeration** — are ids sequential and unscoped? That is the core
   IDOR shape.
7. **State confusion** — can a token or session be reused across contexts — a
   pre-MFA session used post-MFA, a password-reset token accepted as auth?

## Step 5 — Classify what you find

- **Horizontal / lateral:** same privilege level, different victim or tenant
  (user A reads user B; tenant 1 reads tenant 2). Usually IDOR/BOLA or a missing
  tenant filter.
- **Vertical / escalation:** lower privilege gains higher (user → admin) via
  missing function-level authorization, role mass assignment, or a self-grant.
- **Logic:** the action is "allowed" but violates an intended business rule
  (free purchase, double refund, skipped MFA).

Severity for access-control bugs hinges on the **required precondition**
(anonymous > any-authenticated > specific-role) and the **impact of the
reachable object or action**. Capture both explicitly — they are what you score
CVSS from (`PR`, `S`, `C`/`I`).

## MODEL.md template

Write this to `security/MODEL.md` and keep it updated as the scan teaches you
more. Leave a row blank rather than guessing — an invented ownership field
produces invented findings.

```markdown
# App model: <target>

## Stack
- Language / framework: …
- ORM / data layer: …
- Auth / session / RBAC: …
- Multi-tenant: yes/no — tenant key: … (derived from session / taken from request)

## Principals & roles
| Principal | How obtained | Role source | Notable powers |
|-----------|--------------|-------------|----------------|

## Ownership keys
| Model | Owner field | Tenant field | Notes |
|-------|-------------|--------------|-------|

## Routes × authorization
| Method + path | Handler (file:line) | Auth required | Role required | Ownership/tenant check? | Object refs in request | Candidate |
|---------------|---------------------|---------------|---------------|-------------------------|------------------------|-----------|

## Sensitive workflows
| Workflow | Intended steps | State guards | Skip/reorder/replay/race reviewed? | Candidate flaw |
|----------|----------------|--------------|------------------------------------|----------------|

## Hypotheses to check in the scan
- [ ] …
```
