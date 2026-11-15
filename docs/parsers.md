# The parsers

`packages/parsers` turns the files scanners write into findings in one format. It has no I/O and no dependencies on the API: give it text, get findings back. The API's import route, the demo in the browser and the tests all call the same functions.

```ts
import { parse, normalize, dedupe, classify } from "@retest/parsers";

const { findings: raw, warnings } = parse("zap", text);
const { findings, assets } = normalize(raw, { assessmentId, assets: existing });
const { findings: merged } = dedupe([...stored, ...findings]);
const { findings: ready, unmapped, notes } = classify(merged);
```

Four steps, each with one job:

1. **`parse(tool, text, options?)`** reads one tool's file and returns raw findings: what the tool said, and nothing it did not say. Plus `warnings` for anything it skipped or could not read.
2. **`normalize(raw, { assessmentId, assets?, now? })`** places each raw finding on an asset and makes it a finding with the seven fields.
3. **`dedupe(findings)`** folds the same weakness on the same asset into one finding with several sources.
4. **`classify(findings)`** checks every CVSS vector, settles the severity and maps each finding to the standards.

## What each tool's file becomes

Every raw finding has a `rawId` that is stable for the same check at the same place (a template id and matcher, a ZAP plugin id, a Semgrep rule and line, a CVE and package, a Prowler check and resource), so the same file imported twice gives the same findings.

### Nmap

**File:** XML, `nmap -sV --script vulners -oX scan.xml <target>`.

| Nmap says | Raw finding |
| --- | --- |
| An open port with its service and version | One per port: an inventory line in phase 2 (reconnaissance). Scope `tcp/3000`, title `http on tcp/3000 (Node.js Express framework)`, the port line and the CPEs as evidence. No severity: Nmap does not rate anything. |
| A `vulners` table for a CPE | One per table, in phase 3: the CVEs for that version with the top score as a bare number, and an impact that says it is a version match only. A banner is not proof. |
| `smb-security-mode` with message signing disabled | One finding, CWE-924. |

Hosts that are down are skipped; a scan where no host was up says so in a warning. `open|filtered` UDP ports are not reported as open.

### Nuclei

**File:** JSON Lines, `nuclei -u <url> -jsonl -o results.jsonl`.

One raw finding per line (a template and matcher that fired). Kept: the template's severity, CWE ids, CVSS vector and score when the template has them (on the source, unverified), the remediation as the fix, the matched request and response as evidence, any extracted values, and the template's page as the reference. Scope is `METHOD /path`. A line that is not valid JSON or not a Nuclei result is skipped with a warning naming its line number; the rest of the file still imports.

### OWASP ZAP

**File:** the traditional JSON report, `zap-baseline.py -t <url> -J report.json`, or Report > Generate Report > Traditional JSON in the desktop app.

One raw finding per alert, not per instance: twenty URLs missing the same header are one problem with twenty places. The instances become the scope (the first, and how many more) and the evidence (method, URL, parameter, evidence string). ZAP's risk is the severity, its solution the fix, its CWE and WASC ids are kept, its confidence becomes a tag. HTML in ZAP's descriptions is stripped to text.

### Semgrep

**File:** SARIF 2.1.0, `semgrep scan --config p/owasp-top-ten --sarif -o results.sarif`.

One raw finding per result, on a repository asset, scoped to `file:start-end`, with the matched code as evidence and the rule's CWE and OWASP tags. SARIF does not say which repository was scanned, so the import takes `repository` (default `source`). The level is kept as the tool's rating (error high, warning medium, note low): it says how sure the rule is, not how bad the bug would be. A result with no location is skipped with a warning.

### Trivy

**File:** JSON, `trivy image --format json --output trivy.json <image>`.

One raw finding per vulnerability row, on a container-image asset, scoped to `package@version`. Kept: the CVE, the CWEs, the fixed version as the fix (`Upgrade x from a to b`), and the CVSS v3 vector Trivy carries, NVD's first and the vendor's otherwise. A row with no v3 vector is reported with a warning and gets its severity from Trivy's word. Misconfiguration and secret results are not parsed.

### Prowler

**File:** OCSF JSON, `prowler aws -M json-ocsf`.

One raw finding per failed check, on a cloud-account asset, scoped to the resource's ARN. Passed checks are counted and not reported. Manual checks are listed in a warning, since a tool cannot decide them. The CIS benchmark ids are kept as tags. Prowler gives no CWE, so `classify()` maps the common checks (root MFA, password policy, public buckets, open security groups, CloudTrail, encryption, key rotation and others) to CWEs through `CLOUD_CHECKS`; a check it does not know is reported in `unmapped`.

## normalize()

- **Assets.** A port goes on a host asset, a URL on a web-app asset (one per origin), a Semgrep result on a repository, a Trivy row on an image, a Prowler check on a cloud account. Assets passed in are reused, so a second import lands on the same ones.
- **Ids.** A finding's id is a hash of the assessment, the asset, the tool's `rawId` and the scope, so it depends only on what and where the problem is.
- **The seven fields.** What the tool knows goes in. The impact and the fix get a placeholder that says they are not written yet ("Not assessed yet. The scanner reported this; the impact is written after validation."), and the workflow refuses remediation until a person replaces them.
- **Sources.** Each source keeps the tool's own severity word and CVSS claim as the tool gave them. Its reference link is the first http or https URL the tool gave; anything else (a `javascript:` or `data:` URL in a crafted file) is dropped.
- **Evidence.** The tool's output becomes evidence pieces stamped with the tool as their source and not redacted. A piece with a tool as its source never counts as proof for validation.

## dedupe()

Findings are the same when they are on the same asset and have the same fingerprint, tried in this order:

1. the set of CVE ids, when there are any;
2. a short table of checks that different tools name differently (`SAME_WEAKNESS`: the missing security headers and a wildcard CORS policy);
3. the CWE at the same scope;
4. otherwise the tool's `rawId` at the same scope, which only matches a re-import of the same file.

The kept finding takes the first one's id and title, gains the other's sources, evidence and mappings, the higher severity, the wider scope, a real fix or impact in place of a placeholder, and the later phase. Findings on different assets never merge: a Semgrep hit in a route handler and a ZAP alert on the URL it serves may well be the same bug, but proving that is validation, not parsing.

## classify()

- **CVSS.** Every vector a source carries is parsed and scored. A tool's printed score that disagrees with its own vector is noted and the computed score kept. The worst valid vector becomes the finding's risk, and the severity is the one its score gives. A bare score with no vector is turned into a severity word and noted as taken on trust; a CVSS v2 vector is ignored with a note.
- **Standards.** Every CWE goes through the table in `packages/schema` (about two hundred entries), and the finding's OWASP Top 10, OWASP API Top 10, ASVS chapters and CIS Controls are the union of what comes back. A finding with a CVE id is also under A06 Vulnerable and Outdated Components, since a known CVE in a dependency is what that category means. A CWE the table does not know is reported in `unmapped.cwe`, not mapped by guesswork.
- **Idempotent.** Classifying a classified finding changes nothing.

## The fixtures

`packages/parsers/fixtures/` holds one or two files per tool, in the shape of a run against the lab: Juice Shop on 127.0.0.1:3000, its source and its image, two lab machines for the Nmap edge cases, a small AWS lab account for Prowler, and a damaged Nuclei file. They are trimmed to a handful of results so the tests can count every one. The CVE ids, template ids, plugin ids, rule ids and check ids are the real ones, and the CVSS vectors compute to the scores printed next to them. The Nmap port lines are a simplified form of what `nmap` prints: same words, without the column padding.

## Adding a parser

1. Add the tool to `TOOLS` in `packages/schema/src/source.ts`.
2. Write `packages/parsers/src/<tool>.ts`: a loose zod schema for the file (accept what the tool really writes, refuse what it never would), and a function that returns `ParseResult` with `RawFinding[]` and warnings. Fill only what the tool says.
3. Register it in `parse()` in `packages/parsers/src/index.ts`.
4. Add a fixture from a real run against the lab, and tests that count every raw finding and check one of each kind field by field.
5. Add the tool to `TOOL_OWASP_TOP10` in `packages/schema/src/coverage.ts` with the categories it really looks for, so the report's coverage matrix stays honest.
