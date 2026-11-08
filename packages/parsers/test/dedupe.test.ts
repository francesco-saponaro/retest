import { FindingSchema, type Finding } from "@retest/schema";
import { describe, expect, it } from "vitest";
import { dedupe, fingerprint } from "../src/dedupe.js";
import { parseNmap } from "../src/nmap.js";
import { UNASSESSED_IMPACT, UNWRITTEN_FIX, normalize } from "../src/normalize.js";
import { parseNuclei } from "../src/nuclei.js";
import { parseProwler } from "../src/prowler.js";
import { parseSemgrep } from "../src/semgrep.js";
import { parseTrivy } from "../src/trivy.js";
import { parseZap } from "../src/zap.js";
import { fixture } from "./helpers.js";

const now = new Date("2026-11-08T19:00:00Z");
const later = new Date("2026-11-08T19:30:00Z");

function web(): Finding[] {
  const nuclei = normalize(parseNuclei(fixture("nuclei/juice-shop.jsonl")).findings, { assessmentId: "lab", now });
  const zap = normalize(parseZap(fixture("zap/juice-shop.json")).findings, { assessmentId: "lab", now: later, assets: nuclei.assets });
  return [...nuclei.findings, ...zap.findings];
}

describe("fingerprint", () => {
  const findings = web();
  const byRaw = (rawId: string) => findings.find((f) => f.sources[0]!.rawId === rawId)!;

  it("names the same weakness the same way whichever tool reported it", () => {
    expect(fingerprint(byRaw("http-missing-security-headers:content-security-policy"))).toBe("asset-web-127-0-0-1-3000|missing-header:content-security-policy");
    expect(fingerprint(byRaw("10038"))).toBe("asset-web-127-0-0-1-3000|missing-header:content-security-policy");
    expect(fingerprint(byRaw("http-missing-security-headers:permissions-policy"))).toBe(fingerprint(byRaw("10063")));
    expect(fingerprint(byRaw("cors-misconfig:arbitrary-origin"))).toBe(fingerprint(byRaw("10098")));
    // Five missing headers are five findings, not one: a header is a setting of its own.
    expect(fingerprint(byRaw("http-missing-security-headers:referrer-policy"))).not.toBe(fingerprint(byRaw("http-missing-security-headers:content-security-policy")));
  });

  it("uses the CVE ids when there are any", () => {
    const trivy = normalize(parseTrivy(fixture("trivy/juice-shop-image.json")).findings, { assessmentId: "lab", now }).findings;
    expect(fingerprint(trivy[0]!)).toBe("asset-image-bkimminich-juice-shop-v17-1-1|cve:CVE-2024-9143");
    expect(fingerprint(trivy[1]!)).toBe(fingerprint(trivy[0]!));
    expect(fingerprint(trivy[4]!)).not.toBe(fingerprint(trivy[5]!)); // two CVEs in the same package
  });

  it("falls back to the CWE at the place, then to the tool's own id at the place", () => {
    expect(fingerprint(byRaw("10096"))).toBe("asset-web-127-0-0-1-3000|cwe:497@get /main.js");
    expect(fingerprint(byRaw("robots-txt-endpoint"))).toBe("asset-web-127-0-0-1-3000|nuclei:robots-txt-endpoint@get /robots.txt");
    // Query values do not count: `?q=` and `?q=apple` are the same place.
    const a = byRaw("10096");
    const b = { ...a, scope: "GET /main.js?v=1734567890" };
    const c = { ...a, scope: "GET /main.js?v=2" };
    expect(fingerprint(b)).toBe(fingerprint(c));
    expect(fingerprint(b)).not.toBe(fingerprint(a));
  });

  it("keeps findings on different assets apart even when the weakness is the same", () => {
    const semgrep = normalize(parseSemgrep(fixture("semgrep/juice-shop.sarif"), { repository: "juice-shop" }).findings, { assessmentId: "lab", now }).findings;
    const xssInCode = semgrep[5]!;
    expect(xssInCode.mappings.cwe).toEqual([79]);
    const xssOnSite = { ...byRaw("10096"), mappings: { ...byRaw("10096").mappings, cwe: [79] }, scope: xssInCode.scope };
    expect(fingerprint(xssInCode)).not.toBe(fingerprint(xssOnSite));
  });
});

describe("dedupe", () => {
  it("merges what two tools reported about the same site into one finding with two sources", () => {
    const { findings, merged } = dedupe(web(), { now: later });
    expect(web()).toHaveLength(17);
    expect(findings).toHaveLength(14);
    expect(merged).toHaveLength(3);
    for (const f of findings) expect(FindingSchema.safeParse(f).success).toBe(true);

    const csp = findings.find((f) => f.sources.some((s) => s.rawId === "10038"))!;
    expect(csp.sources.map((s) => `${s.tool}:${s.rawId}`)).toEqual(["nuclei:http-missing-security-headers:content-security-policy", "zap:10038"]);
    expect(merged.find((m) => m.into === csp.id)?.from).toHaveLength(1);
  });

  it("keeps the first finding's id and title, and takes the best of the rest", () => {
    const { findings } = dedupe(web(), { now: later });
    const csp = findings.find((f) => f.sources.some((s) => s.rawId === "10038"))!;
    const nucleiCsp = web().find((f) => f.sources[0]!.rawId === "http-missing-security-headers:content-security-policy")!;
    expect(csp.id).toBe(nucleiCsp.id);
    expect(csp.title).toBe(nucleiCsp.title);
    // Nuclei said info, ZAP said medium: the finding carries the higher rating, each source keeps its own.
    expect(csp.risk.severity).toBe("medium");
    expect(csp.sources[0]!.severity).toBe("info");
    expect(csp.sources[1]!.severity).toBe("medium");
    // Nuclei's template has no remediation, so ZAP's solution fills the placeholder; ZAP's wider scope replaces `GET /`, because it contains it.
    expect(nucleiCsp.fix).toBe(UNWRITTEN_FIX);
    expect(csp.fix).toBe("Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.");
    expect(csp.scope).toBe("GET /, GET /ftp, GET /robots.txt");
    // Both tools' evidence, renumbered under the kept id.
    expect(csp.evidence).toHaveLength(2);
    expect(csp.evidence.map((e) => e.id)).toEqual([`${csp.id}-e1`, `${csp.id}-e2`]);
    expect(csp.evidence.every((e) => e.findingId === csp.id)).toBe(true);
    expect(csp.evidence[1]!.source).toEqual({ tool: "zap", rawId: "10038" });
    // CWEs are the union, the latest update wins.
    expect(csp.mappings.cwe).toEqual([693]);
    expect(csp.updatedAt).toBe(later.toISOString());
  });

  it("merges the CORS pair, where the tools disagree on the CWE, and keeps both numbers", () => {
    const { findings } = dedupe(web(), { now: later });
    const cors = findings.find((f) => f.sources.some((s) => s.rawId === "10098"))!;
    expect(cors.sources.map((s) => s.tool)).toEqual(["nuclei", "zap"]);
    expect(cors.mappings.cwe).toEqual([942, 264]);
    expect(cors.risk.severity).toBe("medium"); // Nuclei low, ZAP medium
  });

  it("fills a placeholder impact or fix from the other finding, never the other way round", () => {
    const [a, b] = web().filter((f) => f.sources[0]!.rawId === "http-missing-security-headers:content-security-policy" || f.sources[0]!.rawId === "10038");
    const nucleiNoFix = { ...a!, fix: UNWRITTEN_FIX };
    const { findings } = dedupe([nucleiNoFix, b!], { now: later });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.fix).toBe(b!.fix);
    expect(findings[0]!.impact).toBe(UNASSESSED_IMPACT);
    const zapWithImpact = { ...b!, impact: "Scripts from any origin run in the page." };
    expect(dedupe([a!, zapWithImpact], { now: later }).findings[0]!.impact).toBe("Scripts from any origin run in the page.");
  });

  it("merges the two rows Trivy writes for one CVE in two packages of the same library", () => {
    const trivy = normalize(parseTrivy(fixture("trivy/juice-shop-image.json")).findings, { assessmentId: "lab", now }).findings;
    const { findings, merged } = dedupe(trivy, { now });
    expect(findings).toHaveLength(5);
    const openssl = findings[0]!;
    expect(openssl.scope).toBe("libcrypto3@3.3.2-r0, libssl3@3.3.2-r0");
    expect(openssl.sources.map((s) => s.rawId)).toEqual(["CVE-2024-9143@libcrypto3", "CVE-2024-9143@libssl3"]);
    expect(openssl.mappings.cve).toEqual(["CVE-2024-9143"]);
    expect(merged).toEqual([{ into: openssl.id, from: [trivy[1]!.id] }]);
  });

  it("moves a merged finding to the later phase: a candidate problem outranks an inventory line", () => {
    const nmap = normalize(parseNmap(fixture("nmap/juice-shop.xml")).findings, { assessmentId: "lab", now }).findings;
    const port = { ...nmap[1]!, mappings: { ...nmap[1]!.mappings, cwe: [200] } };
    expect(port.phase).toBe("recon");
    const note: Finding = {
      ...port,
      id: "f-manual",
      phase: "assessment",
      sources: [{ tool: "manual", rawId: "note-1" }],
      evidence: [],
      risk: { severity: "low" },
    };
    expect(fingerprint(note)).toBe(fingerprint(port));
    const { findings } = dedupe([port, note], { now });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.id).toBe(port.id);
    expect(findings[0]!.phase).toBe("assessment");
    expect(findings[0]!.risk.severity).toBe("low");
    expect(findings[0]!.sources).toHaveLength(2);
  });

  it("is idempotent: importing the same file twice adds nothing", () => {
    const once = web();
    const { findings, merged } = dedupe([...once, ...web()], { now: later });
    expect(findings).toHaveLength(14);
    expect(merged).toHaveLength(14); // every kept finding absorbed at least its own second copy
    expect(merged.reduce((n, m) => n + m.from.length, 0)).toBe(20);
    const csp = findings.find((f) => f.sources.some((s) => s.rawId === "10038"))!;
    expect(csp.sources).toHaveLength(2);
    expect(csp.evidence).toHaveLength(2);
  });

  it("leaves findings that share nothing alone, in their order", () => {
    const prowler = normalize(parseProwler(fixture("prowler/lab-account.ocsf.json")).findings, { assessmentId: "lab", now }).findings;
    const { findings, merged } = dedupe(prowler, { now });
    expect(findings).toEqual(prowler);
    expect(merged).toEqual([]);
  });
});
