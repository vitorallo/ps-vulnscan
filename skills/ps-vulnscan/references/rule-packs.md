# Rule packs — what exists, how to choose, how to read them

Packs come from [TikiTribe/claude-secure-coding-rules](https://github.com/TikiTribe/claude-secure-coding-rules)
(MIT). `ps-vulnscan-rules.sh` clones it once into
`~/.cache/ps-vulnscan/claude-secure-coding-rules` and copies the packs you name
into `security/rules/`. `--list` prints the live catalogue with sizes — trust it
over this page if they disagree.

## Catalogue

| Group | Packs |
|---|---|
| `_core` | `owasp-2025` (15 KB), `ai-security` (23), `agent-security` (24), `mcp-security` (61), `rag-security` (50), `graph-database-security` (40) |
| `languages` | python, javascript, typescript, go, rust, java, csharp, cpp, ruby, sql, julia, r |
| `backend` | express, nestjs, fastapi, django, flask — plus AI serving/orchestration: langchain, crewai, autogen, transformers, vllm, triton, torchserve, ray-serve, bentoml, mlflow, modal |
| `frontend` | react, nextjs, vue, svelte, angular |
| `containers` | docker, kubernetes, helm (+ `containers-core`) |
| `cicd` | github-actions, gitlab-ci (+ `cicd-core`) |
| `iac` | terraform, pulumi (+ `iac-core`) |
| `rag` | `rag-core` plus ~25 packs under `rag/<area>/<tool>`: vector stores (pinecone, qdrant, chroma, milvus, pgvector, weaviate, zilliz, azure-ai-search, mongodb-atlas), graph (neo4j, memgraph, neptune, arangodb, tigergraph), document processing (unstructured, docling, llamaparse, parsers-ocr), orchestration (llamaindex, haystack, langchain-loaders, dspy-txtai-ragas), embeddings, chunking, search-rerank, observability |

Names are resolved by directory search, so `express` works; collisions need the
`group/name` form (e.g. `rag/graph`).

## Choosing packs for a scan

Always `core`. Then one per language and framework actually present. The other
`_core` packs are large and specialised — take them only when the stack really
uses that thing, because an irrelevant 61 KB pack is 61 KB of checks that can't
apply.

| What the stack shows | Packs |
|---|---|
| every scan | `core` |
| TypeScript API + React UI | `typescript`, `express` or `nestjs`, `react` |
| Python service | `python`, `fastapi` / `django` / `flask` |
| Go / Rust / Java / C# / Ruby | `go` / `rust` / `java` / `csharp` / `ruby` |
| raw SQL or stored procedures | `sql` |
| ships containers or k8s manifests | `docker`, `kubernetes` or `helm` (`containers-core`) |
| has CI workflows | `github-actions` or `gitlab-ci` (`cicd-core`) |
| infrastructure as code | `terraform` / `pulumi` (`iac-core`) |
| calls an LLM API | `ai-security` |
| is or hosts an agent with tool use | `agent-security` |
| exposes or consumes MCP servers | `mcp-security` (61 KB — only when MCP is really in scope) |
| RAG pipeline | `rag-security` + `rag-core` + the specific `rag/<area>/<tool>` packs |
| graph database | `graph-database-security` |

How to detect these in Stage 1: `package.json` / `pyproject.toml` / `go.mod` /
`pom.xml` / `Gemfile` / `composer.json` / `Cargo.toml` for languages and
frameworks; `Dockerfile*` and `compose*.yml` for containers;
`.github/workflows/` and `.gitlab-ci.yml` for CI; `*.tf` for IaC. For the AI
packs, look for the dependency rather than guessing: `openai`, `anthropic`,
`langchain`, `llamaindex`, `@modelcontextprotocol/sdk`, `mcp`, a vector store
client, a `neo4j`/`gremlin` driver.

`core-all` pulls every `_core` file (~220 KB). Don't — pick.

## How to read a pack as scan checks

Every pack is a list of blocks in the same shape:

```markdown
### Rule: Enforce Server-Side Access Control
**Level**: `strict`
**When**: Any endpoint accessing protected resources...
**Do**:    <secure code>
**Don't**: <vulnerable code>
**Why**:   <consequence>
**Refs**:  OWASP A01:2025, CWE-284, CWE-862
```

Use them like this:

- **`When`** tells you *where in this codebase the rule is even in scope*. Skip
  rules whose `When` has no counterpart here — a rule about GraphQL resolvers in
  a REST-only app is not a passing check, it is an inapplicable one, and saying
  so is more honest than silence.
- **`Don't`** is the search pattern. Translate its shape into a grep for this
  codebase's language and idiom; the pack's example is illustrative, not
  exhaustive.
- **`Do`** is the remediation you quote in the finding — adapted to the local
  style, not pasted verbatim.
- **`Refs`** gives you the CWE and the OWASP category for the finding header.
- **`Level`** (`strict` / `warning` / `advisory`) is an input to severity, not
  severity itself. A `strict` rule broken on an unauthenticated,
  internet-reachable route is critical; the same rule broken in a local dev
  script may not be worth reporting.

Read a pack when you are about to review the code it covers, not all of them up
front — that is the whole reason they sit in `security/rules/` instead of being
auto-loaded into the session.

## Refreshing

A plain run never pulls, so a scan is reproducible and the commit in
`security/rules/.manifest` describes exactly what it was scanned against. Pass
`--update` for the current rules; it re-pulls and reinstalls the packs recorded
in the manifest.
