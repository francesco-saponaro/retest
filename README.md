# Retest

A vulnerability-assessment workbench. You give it the raw output of the scanners you already run (Nmap, Nuclei, OWASP ZAP, Semgrep, Trivy, Prowler) and it turns everything into findings in one format: title, asset and scope, impact, evidence, risk with a CVSS score, fix, retest. The same issue seen by three tools becomes one finding with three sources. Each finding is mapped to the OWASP Top 10, the OWASP API Top 10, ASVS and the CIS Controls, and walked through the six phases of an assessment (scope, recon, vulnerability assessment, validation, risk, remediation and retest) until there is a technical report and an executive summary. I am building it because a scanner only says where a problem might be. Checking it, judging the impact and getting it fixed takes most of the time, and I wanted a place where that work is written down.

Live: https://retest.netlify.app

## A warning about the lab

Retest will ship with a Docker lab (OWASP Juice Shop, ZAP and Nmap bound to 127.0.0.1) so that anyone cloning it gets real findings in minutes. Scanning is not neutral: it sends traffic that can crash a service, trip an alarm or break a law. Never point it at anything you don't own or don't have written permission to test, with the scope and the limits agreed first. The lab exists so that there is always something safe to point it at.

## Status

Being built one stage at a time, an evening each. Done so far:

1. The monorepo and `packages/schema`: the finding format, the six phases, the severity scale, a CVSS v3.1 parser and calculator checked against the examples published by FIRST, and the mapping tables (OWASP Top 10 2021, OWASP API Security Top 10 2023, ASVS v4 chapters, CIS Controls v8, with a lookup by CWE).

Still to come, in order: the parsers, the API, the web app, the workflow rules, the reports, the lab and the command line.

## Layout

```
packages/schema    zod schemas and types: Finding, Asset, Evidence, Assessment, Phase, Severity, CVSS, mappings
packages/parsers   one parser per tool, then normalize(), dedupe() and classify()      (stages 2 and 3)
apps/api           Fastify, Drizzle, PostgreSQL; pglite in tests                       (stage 4)
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

## The schema, in short

`FindingSchema` has the seven fields the roadmap I follow asks of every finding, plus the bookkeeping: which assessment and asset it belongs to, which phase it is in, its status, the tools that reported it and the mappings. Two rules are enforced by the schema itself: a finding marked as a false positive needs a reason, and a finding can only be closed when its retest says it is fixed. `RiskSchema` refuses a severity that disagrees with the CVSS score, and `CvssSchema` refuses a score that is not the one its vector computes to, so nobody can store a made-up number.

`scoreVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")` returns the base score (7.5), the temporal score, the two sub scores and the qualitative severity. `lookupCwe(89)` returns the OWASP category (A03), the ASVS chapters and the CIS controls for SQL injection. The CWE table is a working subset, not the whole list; I add entries as the parsers meet them.

## Licence

MIT.
