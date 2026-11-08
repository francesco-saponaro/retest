import { FindingSchema, type Finding } from "@retest/schema";
import { describe, expect, it } from "vitest";
import { CLOUD_CHECKS, classify, cloudCheckCwes } from "../src/classify.js";
import { dedupe } from "../src/dedupe.js";
import { parseNmap } from "../src/nmap.js";
import { normalize } from "../src/normalize.js";
import { parseNuclei } from "../src/nuclei.js";
import { parseProwler } from "../src/prowler.js";
import { parseSemgrep } from "../src/semgrep.js";
import { parseTrivy } from "../src/trivy.js";
import { parseZap } from "../src/zap.js";
import { fixture } from "./helpers.js";

const now = new Date("2026-11-08T19:00:00Z");
const later = new Date("2026-11-08T20:00:00Z");

function from(tool: "nmap" | "nuclei" | "zap" | "semgrep" | "trivy" | "prowler", file: string): Finding[] {
  const text = fixture(file);
  const raw =
    tool === "nmap"
      ? parseNmap(text).findings
      : tool === "nuclei"
        ? parseNuclei(text).findings
        : tool === "zap"
          ? parseZap(text).findings
          : tool === "semgrep"
            ? parseSemgrep(text, { repository: "juice-shop" }).findings
            : tool === "trivy"
              ? parseTrivy(text).findings
              : parseProwler(text).findings;
  return normalize(raw, { assessmentId: "lab", now }).findings;
}

describe("classify: CVSS", () => {
  it("stores a CVSS vector only after computing its score, and sets the severity from that score", () => {
    const { findings, notes } = classify(from("trivy", "trivy/juice-shop-image.json"), { now: later });
    const jwt = findings[2]!;
    expect(jwt.risk).toEqual({ severity: "critical", cvss: { vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", baseScore: 9.8 } });
    expect(findings[0]!.risk).toEqual({ severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", baseScore: 4.3 } });
    expect(findings[4]!.risk.cvss?.baseScore).toBe(6.1);
    expect(notes).toEqual([]);
    for (const f of findings) expect(FindingSchema.safeParse(f).success).toBe(true);
    expect(jwt.updatedAt).toBe(later.toISOString());
  });

  it("does not take the tool's number on trust: a score that disagrees with its vector is corrected and noted", () => {
    const [jwt] = from("trivy", "trivy/juice-shop-image.json").slice(2, 3);
    const lying: Finding = { ...jwt!, sources: [{ ...jwt!.sources[0]!, cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 9.8 } }] };
    const { findings, notes } = classify([lying], { now: later });
    expect(findings[0]!.risk).toEqual({ severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", baseScore: 5.3 } });
    expect(notes).toEqual([`${jwt!.id}: trivy says 9.8 for CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, which computes to 5.3; 5.3 is used`]);
  });

  it("ignores a vector it cannot parse, says so, and falls back to the severity word", () => {
    const [jwt] = from("trivy", "trivy/juice-shop-image.json").slice(2, 3);
    const broken: Finding = { ...jwt!, sources: [{ ...jwt!.sources[0]!, cvss: { vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", score: 7.5 } }] };
    const { findings, notes } = classify([broken], { now: later });
    expect(findings[0]!.risk).toEqual({ severity: "critical" });
    expect(notes).toEqual([`${jwt!.id}: trivy's vector CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P is not CVSS v3; ignored`]);
  });

  it("takes the worst vector when two tools give different ones", () => {
    const [jwt] = from("trivy", "trivy/juice-shop-image.json").slice(2, 3);
    const two: Finding = {
      ...jwt!,
      sources: [
        { tool: "trivy", rawId: "a", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score: 5.3 } },
        { tool: "nuclei", rawId: "b", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", score: 7.5 } },
      ],
    };
    const { findings } = classify([two], { now: later });
    expect(findings[0]!.risk.cvss).toEqual({ vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 });
    expect(findings[0]!.risk.severity).toBe("high");
  });

  it("verifies the vector Nuclei gives for the metrics endpoint", () => {
    const { findings } = classify(from("nuclei", "nuclei/juice-shop.jsonl"), { now: later });
    const metrics = findings.find((f) => f.sources[0]!.rawId === "prometheus-metrics")!;
    expect(metrics.risk).toEqual({ severity: "medium", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", baseScore: 5.3 } });
  });
});

describe("classify: severity without a vector", () => {
  it("keeps the tool's severity word when there is no vector to check", () => {
    const { findings } = classify(from("zap", "zap/juice-shop.json"), { now: later });
    expect(findings.map((f) => f.risk)).toEqual([{ severity: "medium" }, { severity: "medium" }, { severity: "low" }, { severity: "low" }, { severity: "low" }, { severity: "info" }]);
  });

  it("takes a bare score as a severity word, not as a CVSS, and notes that it was taken on trust", () => {
    const { findings, notes } = classify(from("nmap", "nmap/lab-vms.xml"), { now: later });
    const ssh = findings.find((f) => f.sources[0]!.rawId === "tcp/22/vulners")!;
    expect(ssh.risk).toEqual({ severity: "critical" });
    expect(ssh.risk.cvss).toBeUndefined();
    expect(notes).toContain(`${ssh.id}: severity critical from nmap's bare score 9.8, which has no vector to check`);
    const port = findings.find((f) => f.sources[0]!.rawId === "tcp/22")!;
    expect(port.risk).toEqual({ severity: "info" });
    expect(port.updatedAt).toBe(now.toISOString()); // nothing changed, nothing stamped
  });

  it("uses the highest word among the sources after a merge", () => {
    const nuclei = normalize(parseNuclei(fixture("nuclei/juice-shop.jsonl")).findings, { assessmentId: "lab", now });
    const zap = normalize(parseZap(fixture("zap/juice-shop.json")).findings, { assessmentId: "lab", now, assets: nuclei.assets });
    const merged = dedupe([...nuclei.findings, ...zap.findings], { now }).findings;
    const { findings } = classify(merged, { now: later });
    const csp = findings.find((f) => f.sources.some((s) => s.rawId === "10038"))!;
    expect(csp.risk).toEqual({ severity: "medium" });
    expect(csp.mappings).toEqual({ cwe: [693], cve: [], owaspTop10: ["A05"], owaspApi: [], asvs: ["V14"], cis: [4] });
  });
});

describe("classify: the standards", () => {
  it("maps every CWE through the table and unions the results", () => {
    const { findings, unmapped } = classify(from("semgrep", "semgrep/juice-shop.sarif"), { now: later });
    const sqli = findings[0]!;
    expect(sqli.mappings).toEqual({ cwe: [89], cve: [], owaspTop10: ["A03"], owaspApi: [], asvs: ["V5"], cis: [16] });
    const csrf = findings[6]!;
    expect(csrf.mappings.owaspTop10).toEqual(["A01"]);
    expect(csrf.mappings.asvs).toEqual(["V4"]);
    expect(unmapped).toEqual({ cwe: [], checks: [] });
  });

  it("maps a finding with two CWEs to both categories, in the standards' order", () => {
    const { findings } = classify(from("trivy", "trivy/juice-shop-image.json"), { now: later });
    const jwt = findings[2]!; // CWE-20 (A03) and CWE-327 (A02)
    expect(jwt.mappings.owaspTop10).toEqual(["A02", "A03"]);
    expect(jwt.mappings.asvs).toEqual(["V5", "V6", "V9"]);
    expect(jwt.mappings.cis).toEqual([3, 16]);
    const expressJwt = findings[3]!; // CWE-287 (A07, API2) and CWE-863 (A01, API1)
    expect(expressJwt.mappings.owaspTop10).toEqual(["A01", "A07"]);
    expect(expressJwt.mappings.owaspApi).toEqual(["API1", "API2"]);
  });

  it("reports a CWE the table does not know instead of guessing, and leaves the finding's other mappings intact", () => {
    const zap = from("zap", "zap/juice-shop.json");
    const odd: Finding = { ...zap[3]!, mappings: { ...zap[3]!.mappings, cwe: [749, 123456] } };
    const { findings, unmapped } = classify([odd], { now: later });
    expect(unmapped.cwe).toEqual([123456]);
    expect(findings[0]!.mappings).toEqual({ cwe: [749, 123456], cve: [], owaspTop10: [], owaspApi: [], asvs: ["V5"], cis: [16] });
  });

  it("maps a cloud check by its id, since Prowler gives no CWE", () => {
    expect(cloudCheckCwes("iam_root_mfa_enabled")).toEqual([308]);
    expect(cloudCheckCwes("iam_user_mfa_enabled_console_access")).toEqual([308]);
    expect(cloudCheckCwes("s3_bucket_public_access")).toEqual([284]);
    expect(cloudCheckCwes("s3_bucket_level_public_access_block")).toEqual([284]);
    expect(cloudCheckCwes("ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22")).toEqual([1327]);
    expect(cloudCheckCwes("cloudtrail_multi_region_enabled")).toEqual([778]);
    expect(cloudCheckCwes("iam_avoid_root_usage")).toEqual([269]);
    expect(cloudCheckCwes("iam_password_policy_minimum_length_14")).toEqual([521]);
    expect(cloudCheckCwes("s3_bucket_default_encryption")).toEqual([311]);
    expect(cloudCheckCwes("something_nobody_wrote_down")).toBeUndefined();
    expect(CLOUD_CHECKS.length).toBeGreaterThan(5);
  });

  it("classifies the lab account: every failed check gets a CWE and its standards", () => {
    const { findings, unmapped, notes } = classify(from("prowler", "prowler/lab-account.ocsf.json"), { now: later });
    expect(unmapped).toEqual({ cwe: [], checks: [] });
    expect(notes).toEqual([]);
    expect(findings.map((f) => f.mappings.cwe)).toEqual([[308], [308], [284], [284], [1327], [778], [269]]);
    expect(findings[0]!.mappings).toEqual({ cwe: [308], cve: [], owaspTop10: ["A07"], owaspApi: ["API2"], asvs: ["V2"], cis: [5, 6] });
    expect(findings[4]!.mappings).toEqual({ cwe: [1327], cve: [], owaspTop10: [], owaspApi: [], asvs: [], cis: [4, 12] });
    expect(findings[5]!.mappings.owaspTop10).toEqual(["A09"]);
    expect(findings.map((f) => f.risk.severity)).toEqual(["critical", "high", "critical", "high", "high", "high", "high"]);
  });

  it("names a cloud check it has no mapping for", () => {
    const prowler = from("prowler", "prowler/lab-account.ocsf.json");
    const odd: Finding = { ...prowler[0]!, sources: [{ tool: "prowler", rawId: "ec2_instance_imdsv2_enabled", severity: "high" }] };
    const { unmapped } = classify([odd], { now: later });
    expect(unmapped).toEqual({ cwe: [], checks: ["ec2_instance_imdsv2_enabled"] });
  });

  it("is idempotent", () => {
    const once = classify(from("trivy", "trivy/juice-shop-image.json"), { now: later });
    const twice = classify(once.findings, { now: new Date("2026-11-09T00:00:00Z") });
    expect(twice.findings).toEqual(once.findings);
    expect(twice.notes).toEqual([]);
  });
});
