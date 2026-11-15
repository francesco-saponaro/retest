# Retest

A vulnerability-assessment workbench. You give it the raw output of the scanners you already run (Nmap, Nuclei, OWASP ZAP, Semgrep, Trivy, Prowler) and it turns everything into findings in one format: title, asset and scope, impact, evidence, risk with a CVSS score, fix, retest. The same issue seen by three tools becomes one finding with three sources. Each finding is mapped to the OWASP Top 10, the OWASP API Top 10, ASVS and the CIS Controls, and walked through the six phases of an assessment (scope, recon, vulnerability assessment, validation, risk, remediation and retest) until there is a technical report and an executive summary. I am building it because a scanner only says where a problem might be. Checking it, judging the impact and getting it fixed takes most of the time, and I wanted a place where that work is written down.

Live: https://retest-francesco-saponaro.netlify.app

## A warning about the lab

Retest comes with a Docker lab (OWASP Juice Shop, with Nmap, Nuclei, ZAP and Trivy pointed at it, and every port bound to 127.0.0.1) so that anyone cloning it gets real findings in minutes. Scanning is not neutral: it sends traffic that can crash a service, trip an alarm or break a law. Never point it at anything you don't own or don't have written permission to test, with the scope and the limits agreed first. The lab exists so that there is always something safe to point it at.

## Status

Being built one stage at a time, an evening each. Done so far:

1. The monorepo and `packages/schema`: the finding format, the six phases, the severity scale, a CVSS v3.1 parser and calculator checked against the examples published by FIRST, and the mapping tables (OWASP Top 10 2021, OWASP API Security Top 10 2023, ASVS v4 chapters, CIS Controls v8, with a lookup by CWE).
2. `packages/parsers`, first half: the Nmap (XML) and Nuclei (JSON Lines) parsers, with fixtures and tests that count every result, and `normalize()`, which turns what a parser extracts into findings and assets in the schema's format.
3. `packages/parsers`, second half: the ZAP (JSON report), Semgrep (SARIF), Trivy (JSON) and Prowler (OCSF) parsers, `dedupe()`, which folds the same weakness seen by several tools into one finding with several sources, and `classify()`, which checks every CVSS vector before storing it and maps each finding to the standards through its CWE.
4. `apps/api`: Fastify over PostgreSQL through Drizzle, with PGlite (PostgreSQL in the process) for the tests and for running without a database. Assessments, assets, findings, evidence, imports and the two reports as routes; a bearer token on every request, every row reached through the assessment it belongs to, a rate limit per user, zod on every body; an audit log of every phase and status change and every import; a seed that imports the six fixtures.
5. `apps/web`, the start of it: the list of assessments and the overview of one (the six-phase board, the totals by severity and status, the scope with what each target covers, the assets, the imports), and the demo mode behind the live link, which runs the API's own services in the browser against PostgreSQL compiled to WebAssembly, seeded from the same six scanner files.
6. The findings table (every finding of an assessment, most severe first, with filters by severity, tool, phase, OWASP category and asset, a search over the title and the scope, and rows drawn only where the window is) and the finding page: the seven fields in the roadmap's order with the ones a tool cannot write marked as such, the evidence with a request beside its response and the lines that carry a credential pointed at, a CVSS v3.1 calculator that scores a vector the way the schema does and can store it as the finding's risk, and every tool that reported the finding with what it claimed.
7. The workflow. A finding moves one phase at a time and cannot enter validation without evidence a person captured, nor remediation until the impact and the fix are written; moving back needs a reason. A false positive needs a reason and counts as validated; a risk is accepted only once rated; a retest that found the finding fixed is the only thing that closes it. Every move is a line in the history, which has its own screen. The finding page carries all of it: the phase trail with the next move, the forms that ask why, the impact and the fix written in place, evidence added and redacted, the retest recorded. What a person decided survives a re-import.
8. The reports. One report model is worked out from the rows and rendered three ways: the technical report and the executive summary as markdown from the API, and a report screen in the web app that prints to PDF. Every finding says whether a person verified it; only redacted evidence is shown; the summary has the top risks with verified ones first, a day-by-day trend, a note on CVSS against business risk, and a count of the serious findings that are still only a scanner's claim; the technical report ends with an OWASP Top 10 and ASVS coverage matrix that tells "looked and found nothing" from "nobody looked".

9. The lab, the command line and CI. `lab/run.sh` brings up PostgreSQL, the API, the web app and Juice Shop, scans Juice Shop with Nmap, Nuclei, ZAP baseline and Trivy, imports everything through `apps/cli` into a new assessment and writes both reports. GitHub Actions runs the lint, the types, the tests, both builds and a dependency audit, checks the lab script and builds the lab's images. A review of the project against its own rules: the API now sends security headers on every answer and still no CORS, a source's link can only be http or https, and the demo is served with a content security policy. The phone layout was checked on every screen.

Still to come: the final docs.

## Layout

```
packages/schema    zod schemas and types: Finding, Asset, Evidence, Assessment, Phase, Severity, CVSS, mappings
packages/parsers   one parser per tool, then normalize(), dedupe() and classify()
apps/api           Fastify, Drizzle, PostgreSQL; PGlite in tests and for a quick start
apps/web           Vite, React, TanStack Router and Query, Tailwind; a static demo mode
apps/cli           retest new / import / report / assessments, talking to the API
lab/               docker compose: postgres, api, web, juice-shop, a scanner container; run.sh
```

pnpm workspaces, TypeScript in strict mode everywhere, Vitest for the tests, ESLint with a flat config. Node 22 (`.nvmrc`).

## Run the tests

```
pnpm install
pnpm test          # vitest, every package
pnpm typecheck
pnpm lint
pnpm -r build      # tsc for each package, vite for the web app
```

CI (`.github/workflows/ci.yml`) runs the same commands plus the static demo build and `pnpm audit --prod`, then checks `lab/run.sh` with shellcheck, builds the lab's API and web images, and starts PostgreSQL and the API to check that it answers.

The web tests render the screens with Testing Library against a fake client, and run the demo's in-browser API in Node to check that it produces the same numbers as the API's own seed.

## Run the lab

You need Docker with the compose plugin, and nothing else on the machine: the API image carries the command line.

```
cp lab/.env.example lab/.env      # set POSTGRES_PASSWORD and RETEST_JWT_SECRET (openssl rand -hex 32)
lab/run.sh
```

It starts PostgreSQL, the API (127.0.0.1:3001), the web app (127.0.0.1:8080) and Juice Shop 17.1.1 (127.0.0.1:3000, and 172.30.0.10 on the lab's own network). It builds a scanner image (ZAP's stable image with Nmap and Nuclei added, templates fetched at build time) and runs, against Juice Shop only:

- `nmap -sV --script vulners -p 3000` (the vulners script asks vulners.com about the versions it finds, so the scanner needs to reach the internet);
- `nuclei` with the community templates;
- `zap-baseline.py`, which is passive: it reads what the app sends and attacks nothing;
- Trivy on the Juice Shop image, from a `docker save` copy, so no container gets the Docker socket.

Then it mints a two-hour token, creates an assessment whose scope is exactly Juice Shop's address, URL and image, imports the four files and writes `lab/out/report.md` and `lab/out/summary.md`. Open http://127.0.0.1:8080, paste the token on the Connect screen and the assessment is there with the real findings, waiting to be validated. Semgrep needs Juice Shop's source checked out and Prowler needs a cloud account you own, so neither is in the script; their files import the same way.

## The command line

```
retest assessments
retest new --name "Juice Shop lab" --target 127.0.0.1 --target http://127.0.0.1:3000 --authorized-by me
retest import --tool nmap scan.xml --assessment <id>
retest import --tool semgrep results.sarif --assessment <id> --repository juice-shop
retest report <id>                    # the technical report, to stdout
retest report <id> --summary --out summary.md
```

It reads `RETEST_API_URL` (default `http://127.0.0.1:3001`) and `RETEST_TOKEN`, prints what each import did and the API's own reason when it refuses, and exits 0, 1 when the API or the disk said no, or 2 when the command was wrong. Build it with `pnpm -r build` and run `node apps/cli/dist/cli.js`, or `pnpm -C apps/cli start --` with the arguments. Its tests run every command against the real API in memory.

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
| `GET /findings/:id`, `PATCH /findings/:id` | The seven fields with the evidence and the asset; edit the written fields and the risk (refused once closed). |
| `POST /findings/:id/phase` | Move one finding, under the rules below; 409 with the rule's sentence when it refuses. |
| `POST /findings/:id/status` | `open`, `false-positive` or `accepted-risk`, with a reason; `closed` is refused here. |
| `POST /findings/:id/retest` | `{outcome, notes, testedAt?}`: what the checks showed after the fix. `fixed` closes the finding. |
| `GET /findings/:id/audit` | One finding's own history. |
| `POST /findings/:id/evidence`, `PATCH /evidence/:id` | Add evidence as JSON or as a plain-text body; edit it, mark it redacted. |
| `POST /imports` | A scanner's file, as JSON `{assessmentId, tool, content, filename, repository}` or as the raw body with those in the query. |
| `GET /assessments/:id/report` | The report model both documents are rendered from, as JSON: counts, findings grouped by asset with whether each is verified, top risks, trend, coverage. |
| `GET /assessments/:id/report.md`, `GET /assessments/:id/summary.md` | The technical report and the executive summary, markdown. |

An import parses the file, places what it finds on the assessment's assets, folds it into the findings already there, classifies the result and writes what changed. Importing the same file twice changes nothing. An asset the scope does not cover is recorded as out of scope and the import says so. A finding a person has validated or set aside keeps what the person decided (its risk, its text, its phase and status) when a tool reports it again; only the new sources and evidence are added.

The workflow rules live in `packages/schema/src/workflow.ts` and the API and the web app both call them, so a disabled button on the screen and a 409 from the API give the same sentence. In short: phases are passed one at a time; validation needs at least one piece of evidence without a tool as its source, since a scanner only says where to look; remediation needs the impact and the fix written; moving back needs a reason. A false positive needs a reason and takes the finding to validation if it had not reached it, since that is the phase in which it was found out; an accepted risk needs a reason and a finding that has been rated; a closed finding is read-only until it is reopened, with a reason. A retest is recorded only in remediation, with an outcome that happened and notes on what the checks showed; `fixed` closes the finding, anything else leaves it open for the next round.

## Run the web app

```
pnpm -C apps/web dev              # http://localhost:5173, talking to the API through a /api proxy
VITE_DEMO=1 pnpm -C apps/web build && pnpm -C apps/web preview   # the static demo, as deployed
```

Against the API, the app asks for a token on its Connect screen: mint one with `pnpm -C apps/api token <user>` and paste it. The token stays in the tab's session storage and goes when the tab closes; there is no login, because tokens are minted by whoever holds the API's secret and that is the right shape for a single-team tool. The dev server proxies `/api` to `http://127.0.0.1:3001`, so the API needs no CORS; `VITE_API_URL` points the built app somewhere else.

With `VITE_DEMO=1` there is no server at all. The build bundles PGlite (PostgreSQL compiled to WebAssembly, about 5 MB compressed), the migration, the six fixtures and the API's services, and the page makes the lab when it loads: the two assessments, their imports and the audit lines, through the same `runImport` the API runs. It is the real code path with the network taken out, which is why the demo's numbers are the ones the API tests assert. Nothing is stored: reload the page and the lab is made again, with the same ids, so links to an assessment keep working.

The screens so far: `/` lists the assessments with the phase each is in; `/a/:id` is one assessment's overview, which reads top to bottom as the six phases with the findings in each (the current one marked), the findings by severity and by status, the scope with how many assets each target covers, the assets, and the imports with what each produced. The line under the title says how much of the assessment is still only what a scanner said, because that is the number that decides what to do next.

`/a/:id/findings` is the table: most severe first, with the asset, the CVSS score when there is one, the phase, the tools that reported it, how many pieces of evidence it has and its OWASP categories. The filters (severity, tool, phase, OWASP category, asset) and the search live in the URL, so a filtered list can be linked to and the back button undoes a filter; the rows are virtualised, so an assessment with five hundred findings scrolls like one with twenty. `/a/:id/findings/:fid` is one finding. It opens with where it stands: the six phases as a trail with its own marked, the button for the next phase (disabled, with the rule that refuses it written under it, until the rule is met), and the moves that need a reason: back, false positive, accepted risk, reopen. In remediation the retest form is there too. Then the seven fields in the order the format lists them, with "Not written yet" on the impact and the fix until somebody writes them in place; the evidence, with a form to add a piece a person captured, a captured request shown beside its response, a mark saying whether each piece has been redacted, the text editable, and a note on any line that carries a cookie, an authorization header, a JWT or an AWS key, since those must go before the piece can be marked redacted and reach a report; a CVSS v3.1 calculator that starts from the finding's own vector (or the tool's), scores any change or pasted vector as the schema does, says what each tool claimed, and stores the vector as the finding's risk through the API's own validation; the sources with the tool's rating, its CVSS claim and a link to its own page for the check; and the finding's own history. `/a/:id/audit` is the whole history of an assessment, newest first: who did what, when, and the reason given.

`/a/:id/report` is what goes to the client, on one sheet: the executive summary first, then the technical report. Above it, the number that decides whether it can go yet: how many high or critical findings nobody has verified. Print it (or save as PDF) and the browser chrome goes, the technical report starts on a new page and no finding is split across two. The two buttons beside it download the same documents as markdown, rendered from the same model, so the PDF and the files say the same thing.

## How the reports read

A finding counts as verified when a person has taken it to validation or later and has not marked it a false positive. Everything else is a scanner's claim, and both documents say so on every finding. The top risks list the open findings above informational, most severe first, and at the same severity a verified finding comes before an unverified one.

The coverage matrix is the part that is easy to misread. A blank OWASP category can mean the tools looked and found nothing, or that no tool that ran looks for that kind of issue at all. `packages/schema/src/coverage.ts` holds which categories each tool looks for, the way the lab runs it (ZAP baseline is passive, so it does not look for injection; Trivy only knows packages with CVEs; no scanner looks at design), and the matrix marks each row Findings, Looked and found nothing, or Not tested. ASVS rows are filled from the findings only: a scanner can show a requirement failing, never a chapter passing. Any finding with a CVE id also counts under A06, since a known CVE in someone else's code is what that category means.

The trend is drawn from the imports (findings created each day) and the history (closed by a retest, set aside as false positive or accepted, reopened), with the open count carried from day to day.

The demo takes three of the lab's findings through the workflow after the imports, so every state of it is on screen: the CORS finding validated with a curl capture and rated, ZAP's timestamp alert marked a false positive, and the jsonwebtoken CVE confirmed in the container, written up and retested against the same image, where it is still open. Nothing is closed; recording a retest that found it fixed closes one, and a reload makes the lab again.

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

## How Retest protects itself

A tool that holds unfixed vulnerabilities and the evidence for them is worth attacking, so I held it to the checks it helps run on other people's apps.

- **Who you are.** Every route but `/health` needs a bearer token: HS256 with the algorithm pinned on verification, `sub` and `exp` required, and a secret of at least 32 characters with no default. There is no login form to brute-force; tokens are minted by whoever holds the secret.
- **What you can see.** Every row is reached through its assessment, and an assessment is visible to its owner or an admin. Someone else's assessment answers 404, the same as one that does not exist.
- **What you can send.** Every body and query is checked by a strict zod schema (unknown fields refused), imports have their own body size limit and a tighter rate limit, and every user (or address, without a valid token) has a rate limit counted before authentication.
- **What comes back.** Errors say what was wrong with the request and nothing about the server; a 500 is "internal error". Every answer carries `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Referrer-Policy: no-referrer`. There is no CORS: the web app reaches the API on its own origin, through the dev server's proxy or nginx in the lab, so no other site can read an answer.
- **What it shows.** Everything a scanner file contains is untrusted. React escapes all of it, nothing is rendered as HTML, and a source's link is kept only if it is http or https, so a crafted file cannot slip a `javascript:` link onto a finding. Evidence reaches a report only once it is marked redacted, and it cannot be marked while a line still carries a cookie, a token or a key.
- **Where it runs.** The demo is served with a content security policy that allows scripts from its own origin and WebAssembly for the in-browser database, and nothing else. The lab binds every port to 127.0.0.1 and keeps its secrets in `lab/.env`, which git ignores.

`pnpm audit --prod` finds nothing. The full audit reports two moderate advisories in development tools only (esbuild's dev server, pulled in by drizzle-kit, and minimatch inside ESLint); neither ships or runs in the API, the web app or the command line.

## Licence

MIT.
