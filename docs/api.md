# The API

Fastify 5 over PostgreSQL (PGlite in tests and for a quick start). Every route is in `apps/api/src/routes/`, the work they do in `apps/api/src/services/`, and every one of them has integration tests in `apps/api/test/` that run against a real PostgreSQL in the process.

## Everything every route shares

**Authentication.** Every route except `GET /health` needs `Authorization: Bearer <token>`. Tokens are HS256 JWTs signed with `RETEST_JWT_SECRET` (32 characters or more, no default), with `sub` (the user) and `exp` required and an optional `role`, `assessor` (the default) or `admin`. The algorithm is pinned when verifying, so a token that says `alg: none` or `RS256` is refused. Mint one with `pnpm -C apps/api token <user> [assessor|admin] [hours]`. A missing, expired or bad token answers `401 {"error": "..."}`.

**Authorization.** An assessment belongs to the user who created it. Its owner and any admin can see and change it, and everything under it: assets, findings, evidence, imports, history, reports. Anyone else gets `404`, the same answer as for an assessment that does not exist, so ids cannot be probed. A finding or a piece of evidence reached by its own id (`/findings/:id`, `/evidence/:id`) is checked through its assessment the same way.

**Bodies.** JSON, checked by a strict zod schema: an unknown field is refused, not ignored. A refused body answers `400 {"error": "invalid body", "issues": [{"path": "...", "message": "..."}]}`; a refused query or path parameter says `invalid query` or `invalid params`. A body the schema accepted but a domain rule did not (a severity that disagrees with its CVSS score, say) answers `400 {"error": "invalid data", "issues": [...]}`.

**State.** A request that is well formed but that the current state refuses answers `409 {"error": "<the rule, in one sentence>"}`: a finding moved two phases at once, validated without evidence a person captured, closed by hand; an import into a closed assessment.

**Limits.** Every user (or address, without a valid token) may make 300 requests a minute (`RATE_LIMIT_MAX`), counted before authentication; `POST /imports` has its own limit of 20 a minute (`IMPORT_RATE_LIMIT_MAX`) and takes bodies up to 20 MB. Over the limit answers `429`.

**Headers.** Every answer, errors included, carries `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Referrer-Policy: no-referrer`. There is no CORS: the web app reaches the API on its own origin.

**Errors.** `500 {"error": "internal error"}`, with the details in the server's log only. An unknown route is `404 {"error": "not found"}`.

**Lists** answer `{"items": [...]}`. Times are ISO 8601 in UTC.

## Routes

### Health

| Method and path | Auth | What it does |
| --- | --- | --- |
| `GET /health` | none | `{"ok": true}`. For the lab script and a load balancer. |

### Assessments

| Method and path | Body or query | Answer |
| --- | --- | --- |
| `POST /assessments` | `{name, client?, scope: {targets: string[], exclusions?: string[], authorizedBy, authorizedAt?, startsAt?, endsAt?}}` | `201` the assessment, in phase `scope` and status `draft`, owned by the caller. |
| `GET /assessments` | | The caller's assessments (an admin's: all), newest first. |
| `GET /assessments/:id` | | The assessment with `totals`: findings and assets, and findings by severity, phase and status. |
| `PATCH /assessments/:id` | `{name?, client? (null clears it), scope?}` | The assessment. An empty body is `400 nothing to change`. |
| `POST /assessments/:id/phase` | `{phase, reason?}` | The assessment. Written to the history. |
| `POST /assessments/:id/status` | `{status: draft \| active \| closed, reason?}` | The assessment. Written to the history. A closed assessment refuses imports. |
| `GET /assessments/:id/audit` | | The history: every import and every phase, status and retest change, oldest first, each with who, when, from, to and the reason. |
| `DELETE /assessments/:id` | | `204`. Everything under it goes too. |

### Assets

| Method and path | Body | Answer |
| --- | --- | --- |
| `POST /assessments/:id/assets` | `{kind, name, host?, port?, url?, inScope?, tags?}` | `201` the asset. A web app or an API needs a `url`. |
| `GET /assessments/:id/assets` | | The assets, by name. |
| `GET /assessments/:id/assets/:assetId` | | One asset. |
| `PATCH /assessments/:id/assets/:assetId` | any of the fields above; `null` clears `host`, `port` or `url` | The asset. |

Imports create assets on their own; these routes are for what a person adds or corrects.

### Findings

| Method and path | Body or query | Answer |
| --- | --- | --- |
| `POST /assessments/:id/findings` | `{title, assetId, scope, impact, fix, risk, phase? (default validation), mappings?, evidence?}` | `201` a finding a person found by hand, with `manual` as its source, classified like an imported one. |
| `GET /assessments/:id/findings` | `severity, phase, status, tool, owasp` (each a comma-separated list), `assetId`, `q` (title and scope, any case), `limit` (1 to 500, default 100), `offset` | `{items, total, limit, offset}`, most severe first, then by title. Each item is the finding without its evidence and with `evidenceCount`. |
| `GET /findings/:id` | | The finding with its evidence and its asset. |
| `PATCH /findings/:id` | `{title?, assetId?, scope?, impact?, fix?, risk?, mappings?}` | The finding. `risk` is kept as given (its severity must match its CVSS score). `phase`, `status`, `retest` and `sources` are refused here: they have their own routes. A closed finding is `409`. |
| `POST /findings/:id/phase` | `{phase, reason?}` | The finding. One phase forward at a time; validation needs evidence with no tool as its source; remediation needs the impact and the fix written; going back needs a reason; only an open finding moves. Otherwise `409` with the rule. |
| `POST /findings/:id/status` | `{status: open \| false-positive \| accepted-risk, reason?}` | The finding. A false positive or an accepted risk needs a reason, an accepted risk needs a rated finding (phase risk or later), reopening needs a reason. `closed` is refused: a retest closes. A false positive found before validation is moved to validation first. |
| `POST /findings/:id/retest` | `{outcome: fixed \| partially-fixed \| not-fixed, notes, testedAt?}` | The finding. Only in remediation and only when open. `fixed` closes it. |
| `GET /findings/:id/audit` | | This finding's history. |
| `POST /findings/:id/evidence` | JSON `{kind, title?, content, redacted?, capturedAt?}`, or the text itself as `text/plain` with `kind` and `title` in the query | `201` the piece, numbered after the finding's last one, with no tool as its source. |
| `PATCH /evidence/:id` | `{title?, content?, redacted?}` | The piece. |

### Imports

| Method and path | Body | Answer |
| --- | --- | --- |
| `POST /imports` | JSON `{assessmentId, tool, content, filename?, repository?}`, or the file itself as the body (`text/plain`, `text/xml`, `application/xml`, `application/x-ndjson`, `application/jsonl`, `application/octet-stream`) with the other fields in the query | `201 {id, tool, filename, parsed, created, merged, assetsCreated, warnings, unmapped: {cwe, checks}, notes, at}`. `tool` is one of `nmap`, `nuclei`, `zap`, `semgrep`, `trivy`, `prowler`; `repository` names the repository for a Semgrep SARIF file. |
| `GET /assessments/:id/imports` | | Every import, newest first. |

An import parses the file, places what it finds on the assessment's assets, folds it into the findings already there, classifies the result and writes it in one transaction. Importing the same file twice changes nothing. An asset the scope does not cover is recorded as out of scope, with a warning. A finding a person has validated or set aside keeps what the person decided. [parsers.md](parsers.md) says what each tool's file becomes.

### Reports

| Method and path | Answer |
| --- | --- |
| `GET /assessments/:id/report` | The report model, JSON: `counts` (with `verified`, `unverifiedOpen`, by severity and by phase), `groups` (assets with their findings, each marked `verified`), `topRisks`, `unverifiedSerious`, `trend` (one row per day: found, closed, set aside, reopened, open at the end of the day) and `coverage` (`toolsRun`, and the OWASP Top 10 and ASVS rows with `state`: found, clean or not-tested). |
| `GET /assessments/:id/report.md` | The technical report, `text/markdown`: per asset, per finding, the seven fields, only redacted evidence, then the coverage matrices. |
| `GET /assessments/:id/summary.md` | The executive summary, `text/markdown`. |

All three come from the same model, built by the pure functions in `apps/api/src/report/`.

## Running it

```
export RETEST_JWT_SECRET="$(openssl rand -hex 32)"
pnpm install && pnpm -r build
pnpm -C apps/api seed me                  # optional: the lab assessment for user "me"
pnpm -C apps/api start                    # http://127.0.0.1:3001
TOKEN=$(pnpm -s -C apps/api token me)
curl -s -H "authorization: Bearer $TOKEN" localhost:3001/assessments
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `RETEST_JWT_SECRET` | none (required) | The token secret, 32 characters or more. |
| `DATABASE_URL` | `pglite` | `postgres://...`, or `pglite` (in memory), or `pglite:<dir>` (on disk). Migrations run at start. |
| `PORT` | `3001` | |
| `HOST` | `127.0.0.1` | Loopback by default; set `0.0.0.0` on purpose. |
| `RATE_LIMIT_MAX` | `300` | Requests a minute per user or address. |
| `IMPORT_RATE_LIMIT_MAX` | `20` | Imports a minute per user or address. |
| `SEED_OWNER` | `lab` | Who owns the seeded assessment. |
| `LOG` | `true` | Fastify's request log. |
