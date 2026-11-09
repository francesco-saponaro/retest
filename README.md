# Retest

A vulnerability-assessment workbench. You give it the raw output of the scanners you already run (Nmap, Nuclei, OWASP ZAP, Semgrep, Trivy, Prowler) and it turns everything into findings in one format: title, asset and scope, impact, evidence, risk with a CVSS score, fix, retest. The same issue seen by three tools becomes one finding with three sources. Each finding is mapped to the OWASP Top 10, the OWASP API Top 10, ASVS and the CIS Controls, and walked through the six phases of an assessment (scope, recon, vulnerability assessment, validation, risk, remediation and retest) until there is a technical report and an executive summary. I am building it because a scanner only says where a problem might be. Checking it, judging the impact and getting it fixed takes most of the time, and I wanted a place where that work is written down.

Live: https://retest-francesco-saponaro.netlify.app

## A warning about the lab

Retest will ship with a Docker lab (OWASP Juice Shop, ZAP and Nmap bound to 127.0.0.1) so that anyone cloning it gets real findings in minutes. Scanning is not neutral: it sends traffic that can crash a service, trip an alarm or break a law. Never point it at anything you don't own or don't have written permission to test, with the scope and the limits agreed first. The lab exists so that there is always something safe to point it at.

## Status

Being built one stage at a time, an evening each. Done so far:

1. The monorepo and `packages/schema`: the finding format, the six phases, the severity scale, a CVSS v3.1 parser and calculator checked against the examples published by FIRST, and the mapping tables (OWASP Top 10 2021, OWASP API Security Top 10 2023, ASVS v4 chapters, CIS Controls v8, with a lookup by CWE).
2. `packages/parsers`, first half: the Nmap (XML) and Nuclei (JSON Lines) parsers, with fixtures and tests that count every result, and `normalize()`, which turns what a parser extracts into findings and assets in the schema's format.
3. `packages/parsers`, second half: the ZAP (JSON report), Semgrep (SARIF), Trivy (JSON) and Prowler (OCSF) parsers, `dedupe()`, which folds the same weakness seen by several tools into one finding with several sources, and `classify()`, which checks every CVSS vector before storing it and maps each finding to the standards through its CWE.
4. `apps/api`: Fastify over PostgreSQL through Drizzle, with PGlite (PostgreSQL in the process) for the tests and for running without a database. Assessments, assets, findings, evidence, imports and the two reports as routes; a bearer token on every request, every row reached through the assessment it belongs to, a rate limit per user, zod on every body; an audit log of every phase and status change and every import; a seed that imports the six fixtures.

Still to come, in order: the web app, the workflow rules, the reports properly, the lab and the command line.

## Layout

```
packages/schema    zod schemas and types: Finding, Asset, Evidence, Assessment, Phase, Severity, CVSS, mappings
packages/parsers   one parser per tool, then normalize(), dedupe() and classify()
apps/api           Fastify, Drizzle, PostgreSQL; PGlite in tests and for a quick start
apps/web           Vite, React, TanStack Router and Query, Tailwind; a static demo mode (stages 5 to 8)
apps/cli           retest import / retest report, talking to the API                   (stage 9)
lab/               docker compose: postgres, api, web, juice-shop, a scanner container (stage 9)
```

pnpm workspaces, TypeScript in strict mode everywhere, Vitest for the tests, ESLint with a flat config. Node 22 (`.nvmrc`).

## Run the tests

```
pnpm install
pnpm test          # vitest, every package
pnpm typecheck
pnpm lint
pnpm -r build      # tsc for each package
```

Until the web app exists, `dist/` holds a placeholder page so that the deploy has something to serve.

## Run the API

```
export RETEST_JWT_SECRET="$(openssl rand -hex 32)"   # at least 32 characters; there is no default
pnpm -r build
pnpm -C apps/api seed me          # the lab assessment for user "me", in an in-memory database
pnpm -C apps/api start            # http://127.0.0.1:3001
```

Without `DATABASE_URL` the API runs PGlite in memory, and everything is gone when it stops. Set `DATABASE_URL=pglite:./data` to keep it on disk, or `DATABASE_URL=postgres://user:pass@host:5432/retest` for PostgreSQL 16, where `pnpm -C apps/api migrate` applies the migrations in `apps/api/drizzle/`. `HOST` is `127.0.0.1` unless you say otherwise; `PORT` is 3001.

Every route except `/health` needs `Authorization: Bearer <token>`. Tokens are HS256 JWTs signed with `RETEST_JWT_SECRET`; mint one with `pnpm -C apps/api token <user> [assessor|admin] [hours]`. A user sees only the assessments they created; an admin sees all of them.

```
TOKEN=$(pnpm --silent -C apps/api token me)
curl -s -X POST localhost:3001/assessments -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"Juice Shop","scope":{"targets":["127.0.0.1","http://127.0.0.1:3000"],"authorizedBy":"me"}}'
curl -s -X POST "localhost:3001/imports?assessmentId=<id>&tool=nmap&filename=scan.xml" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: text/xml' --data-binary @scan.xml
curl -s "localhost:3001/assessments/<id>/findings?severity=high,critical" -H "authorization: Bearer $TOKEN"
curl -s "localhost:3001/assessments/<id>/summary.md" -H "authorization: Bearer $TOKEN"
```

The routes:

| Route | What it does |
| --- | --- |
| `POST /assessments`, `GET /assessments`, `GET /assessments/:id` | Create, list, read (with totals by severity, phase and status). |
| `PATCH /assessments/:id`, `DELETE /assessments/:id` | Name, client and scope; delete with everything under it. |
| `POST /assessments/:id/phase`, `POST /assessments/:id/status` | Move the engagement; each change is an audit line. |
| `GET /assessments/:id/audit`, `GET /assessments/:id/imports` | What happened, in order. |
| `POST /assessments/:id/assets`, `GET /assessments/:id/assets`, `GET`/`PATCH /assessments/:id/assets/:assetId` | The things under test. An asset is keyed by (assessment, id). |
| `POST /assessments/:id/findings` | A finding made by hand, the seven fields in. |
| `GET /assessments/:id/findings` | Filters `severity`, `phase`, `status`, `tool`, `owasp`, `assetId`, `q`, each a comma-separated list; `limit` and `offset`. |
| `GET /findings/:id`, `PATCH /findings/:id` | The seven fields with the evidence and the asset; edit the written fields and the risk. |
| `POST /findings/:id/phase`, `GET /findings/:id/audit` | Move one finding; its own audit lines. |
| `POST /findings/:id/evidence`, `PATCH /evidence/:id` | Add evidence as JSON or as a plain-text body; mark it redacted. |
| `POST /imports` | A scanner's file, as JSON `{assessmentId, tool, content, filename, repository}` or as the raw body with those in the query. |
| `GET /assessments/:id/report.md`, `GET /assessments/:id/summary.md` | The technical report and the executive summary, markdown. |

An import parses the file, places what it finds on the assessment's assets, folds it into the findings already there, classifies the result and writes what changed. Importing the same file twice changes nothing. An asset the scope does not cover is recorded as out of scope and the import says so. The status, retest and false-positive rules of the workflow are not routes yet; the schema already refuses a closed finding without a retest that says fixed.

## The schema, in short

`FindingSchema` has the seven fields the roadmap I follow asks of every finding, plus the bookkeeping: which assessment and asset it belongs to, which phase it is in, its status, the tools that reported it and the mappings. Two rules are enforced by the schema itself: a finding marked as a false positive needs a reason, and a finding can only be closed when its retest says it is fixed. `RiskSchema` refuses a severity that disagrees with the CVSS score, and `CvssSchema` refuses a score that is not the one its vector computes to, so nobody can store a made-up number.

`scoreVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")` returns the base score (7.5), the temporal score, the two sub scores and the qualitative severity. `lookupCwe(89)` returns the OWASP category (A03), the ASVS chapters and the CIS controls for SQL injection. The CWE table is a working subset, not the whole list; I add entries as the parsers meet them.

## The parsers, in short

`parse(tool, text)` returns raw findings: what the tool said and nothing it did not say. There is one parser per tool.

- `nmap` (XML, `-oX`): one raw finding per open port (an inventory line, phase 2 of the assessment), one per `vulners` match (a list of CVEs for the version in the banner, a candidate for phase 3, unverified) and one when `smb-security-mode` reports that SMB signing is off. Nmap does not rate anything, so its findings carry no severity.
- `nuclei` (JSON Lines, `-jsonl`): one per matched template, keeping its severity, its CWE and CVSS classification when the template has them, the request and the response that matched, and the remediation text.
- `zap` (the JSON report from `zap-baseline.py -J` or the desktop app): one per alert, not per instance. The instances become the scope and the evidence; ZAP's risk is the severity, its solution the fix, its confidence a tag.
- `semgrep` (SARIF, `--sarif`): one per result, on the repository, at `file:lines`, with the matched code as evidence and the rule's CWE. SARIF does not name the repository, so `parse("semgrep", text, { repository })` takes it. The level (error, warning, note) is kept as high, medium or low: it says how sure the rule is, not how bad the bug would be.
- `trivy` (JSON, `trivy image -f json`): one per vulnerability row, on the image, with the package and version as the scope, the CVE, the CWEs, the CVSS v3 vector Trivy carries (NVD's first) and the fixed version as the fix.
- `prowler` (OCSF, `-M json-ocsf`): one per failed check, on the cloud account, with the resource as the scope. Passed checks are counted, manual ones are listed as a warning. Prowler gives no CWE; `classify()` knows what the common checks are about.

`normalize(raw, { assessmentId })` places each raw finding on an asset (a host for a port, a web app for a URL, a repository, an image or a cloud account for the rest, reusing the assets you pass in), gives it an id that depends only on what and where it is (so importing the same file twice gives the same ids), and fills the seven fields: what the tool knows goes in, and the impact and the fix get a placeholder that says they are not written yet. Each source keeps the tool's own rating (its severity word, its CVSS vector and score) as the tool gave it.

`dedupe(findings)` folds findings that are the same weakness on the same asset into one finding with several sources. "The same" is decided by a fingerprint, in this order: the CVE ids when there are any; a short table of checks that different tools name differently (a missing header, a wildcard CORS policy); the CWE at the same place; and otherwise the tool's own id at the same place, which only matches a re-import. Findings on different assets never merge: a Semgrep hit in a route handler and a ZAP alert on the URL it serves may be the same bug, but proving that is validation, not parsing. The kept finding gains the other's sources and evidence, the higher severity, the wider scope, a real fix in place of a placeholder, and the later phase.

`classify(findings)` settles the risk and fills the mappings. A CVSS vector from a tool is parsed and scored here, compared with the score the tool printed, and only then stored, with the severity set from the computed score; a score with no vector is taken as a severity word and noted as taken on trust. Every CWE goes through the table in `packages/schema` and the OWASP Top 10, OWASP API Top 10, ASVS and CIS columns are the union of what comes back. A CWE or a cloud check the tables do not know is reported in `unmapped`, not mapped by guesswork.

The fixtures in `packages/parsers/fixtures/` are in the shape of a run against the lab (Juice Shop on 127.0.0.1:3000, scanned from the same machine; the Juice Shop source and image; two lab VMs for the Nmap edge cases; a small AWS lab account for Prowler), trimmed to a handful of results so that the tests can count them exactly. The CVE ids, template ids, plugin ids, rule ids and check ids are the real ones; the CVSS vectors compute to the scores printed next to them. The port lines in the Nmap evidence are a simplified form of what `nmap` prints: same words, without the column padding.

## Licence

MIT.
