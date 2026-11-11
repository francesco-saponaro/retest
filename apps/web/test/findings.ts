import type { Finding, Severity } from "@retest/schema";
import type { FindingSummary } from "@retest/api/rows.js";
import type { FindingDetail } from "@retest/api/services/findings.js";
import { juiceAssets } from "./fake.js";

/**
 * Findings shaped like the lab's own: the same titles, scopes, sources and mappings the six fixtures
 * produce, with the ids shortened. `jwt` carries a CVSS vector from Trivy, `cors` was seen by two
 * tools, `login` is a code finding with no vector, `http` is an inventory line from Nmap.
 */
const at = "2026-11-10T18:00:00.000Z";
const placeholderImpact = "Not assessed yet. The scanner reported this; the impact is written after validation.";
const placeholderFix = "Not written yet. The fix is decided after validation.";
const noMappings = { cwe: [], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [] };

function finding(partial: Partial<Finding> & Pick<Finding, "id" | "title" | "assetId" | "scope" | "risk" | "sources">): Finding {
  return {
    assessmentId: "a-juice",
    impact: placeholderImpact,
    fix: placeholderFix,
    evidence: [],
    phase: "assessment",
    status: "open",
    mappings: noMappings,
    createdAt: at,
    updatedAt: at,
    ...partial,
  };
}

export const jwt = finding({
  id: "f-jwt",
  title: "CVE-2015-9235 in jsonwebtoken 0.4.0: Verification Bypass in jsonwebtoken",
  assetId: "asset-image-juice-shop",
  scope: "jsonwebtoken@0.4.0",
  risk: { severity: "critical", cvss: { vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: 9.8 } },
  fix: "Upgrade jsonwebtoken from 0.4.0 to 4.2.2 or later.",
  sources: [{ tool: "trivy", rawId: "CVE-2015-9235@jsonwebtoken", severity: "critical", reference: "https://avd.aquasec.com/nvd/cve-2015-9235", cvss: { score: 9.8, vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }],
  mappings: { cwe: [20, 327], cve: ["CVE-2015-9235"], owaspTop10: ["A02", "A03"], owaspApi: [], asvs: ["V5", "V6", "V9"], cis: [3, 16] },
  evidence: [
    {
      id: "ev-jwt-1",
      findingId: "f-jwt",
      kind: "scanner-output",
      title: "Node.js: jsonwebtoken@0.4.0",
      content: "package: jsonwebtoken\ninstalled: 0.4.0\nfixed in: 4.2.2\nstatus: fixed\npath: juice-shop/node_modules/jsonwebtoken/package.json",
      redacted: false,
      source: { tool: "trivy", rawId: "CVE-2015-9235@jsonwebtoken" },
    },
  ],
});

export const corsRequest = [
  "GET /rest/products/search?q= HTTP/1.1",
  "Host: 127.0.0.1:3000",
  "Origin: https://example.com",
  "Cookie: token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl",
  "Accept: */*",
  "",
  "",
  "HTTP/1.1 200 OK",
  "Access-Control-Allow-Origin: *",
  "Content-Type: application/json; charset=utf-8",
  "",
  '{"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)"}]}',
].join("\n");

export const cors = finding({
  id: "f-cors",
  title: "CORS Misconfiguration: arbitrary-origin",
  assetId: "asset-web-127-0-0-1-3000",
  scope: "GET /rest/products/search?q=, GET /api/Quantitys/, GET /rest/user/whoami",
  risk: { severity: "medium" },
  fix: 'Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains.',
  sources: [
    { tool: "nuclei", rawId: "cors-misconfig:arbitrary-origin", severity: "low", reference: "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/generic/cors-misconfig.yaml" },
    { tool: "zap", rawId: "10098", severity: "medium", reference: "https://www.zaproxy.org/docs/alerts/10098/" },
  ],
  mappings: { cwe: [942, 264], cve: [], owaspTop10: ["A01", "A05"], owaspApi: ["API8"], asvs: ["V4", "V14"], cis: [4, 6, 16] },
  evidence: [
    { id: "ev-cors-1", findingId: "f-cors", kind: "request-response", title: "GET http://127.0.0.1:3000/rest/products/search?q=", content: corsRequest, redacted: false, source: { tool: "nuclei", rawId: "cors-misconfig:arbitrary-origin" } },
    {
      id: "ev-cors-2",
      findingId: "f-cors",
      kind: "scanner-output",
      title: "3 instances reported by ZAP",
      content: "GET http://127.0.0.1:3000/rest/products/search?q=\n  evidence: Access-Control-Allow-Origin: *\nGET http://127.0.0.1:3000/api/Quantitys/\n  evidence: Access-Control-Allow-Origin: *",
      redacted: true,
      source: { tool: "zap", rawId: "10098" },
    },
  ],
});

export const login = finding({
  id: "f-login",
  title: "express-sequelize-injection in routes/login.ts",
  assetId: "asset-repo-juice-shop",
  scope: "routes/login.ts:34-36",
  risk: { severity: "high" },
  sources: [{ tool: "semgrep", rawId: "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection@routes/login.ts:34", severity: "high" }],
  mappings: { cwe: [89], cve: [], owaspTop10: ["A03"], owaspApi: [], asvs: ["V5"], cis: [16] },
  evidence: [{ id: "ev-login-1", findingId: "f-login", kind: "scanner-output", title: "routes/login.ts:34-36", content: "models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}'`)", redacted: false }],
});

export const http = finding({
  id: "f-http",
  title: "http on tcp/3000 (Node.js Express framework)",
  assetId: "asset-host-127-0-0-1",
  scope: "tcp/3000",
  risk: { severity: "info" },
  phase: "recon",
  sources: [{ tool: "nmap", rawId: "tcp/3000" }],
});

export const mfa = finding({
  id: "f-mfa",
  title: "MFA is not enabled for root account.",
  assetId: "asset-cloud-123456789012",
  scope: "arn:aws:iam::123456789012:root",
  risk: { severity: "critical" },
  fix: "Using IAM console navigate to Dashboard and expand Activate MFA on your root account.",
  sources: [{ tool: "prowler", rawId: "iam_root_mfa_enabled", severity: "critical" }],
  mappings: { cwe: [308], cve: [], owaspTop10: ["A07"], owaspApi: ["API2"], asvs: ["V2"], cis: [5, 6] },
});

export const juiceFindings: Finding[] = [jwt, mfa, login, cors, http];

export function summaryOf(f: Finding): FindingSummary {
  const { evidence, ...rest } = f;
  return { ...rest, evidenceCount: evidence.length };
}

export function detailOf(f: Finding): FindingDetail {
  const asset = juiceAssets.find((a) => a.id === f.assetId);
  if (!asset) throw new Error(`no fake asset ${f.assetId}`);
  return { ...f, asset };
}

/** `n` findings of a flat kind, to fill a table past one screen. */
export function manyFindings(n: number, severity: Severity = "low"): FindingSummary[] {
  return Array.from({ length: n }, (_, i) =>
    summaryOf(finding({ id: `f-many-${i}`, title: `Missing header ${i + 1}`, assetId: "asset-web-127-0-0-1-3000", scope: `GET /page/${i + 1}`, risk: { severity }, sources: [{ tool: "nuclei", rawId: `header-${i}` }] })),
  );
}
