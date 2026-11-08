import { describe, expect, it } from "vitest";
import { parseProwler, parseProwlerOcsf, prowlerFindings } from "../src/prowler.js";
import { fixture } from "./helpers.js";

const ocsf = fixture("prowler/lab-account.ocsf.json");

describe("parseProwlerOcsf", () => {
  const checks = parseProwlerOcsf(ocsf);

  it("reads every check result, pass or fail", () => {
    expect(checks).toHaveLength(10);
    expect(checks.map((c) => c.status)).toEqual(["FAIL", "FAIL", "PASS", "FAIL", "FAIL", "PASS", "FAIL", "FAIL", "FAIL", "MANUAL"]);
  });

  it("reads one result whole: check, severity, account, resource, texts", () => {
    const mfa = checks[0]!;
    expect(mfa.checkId).toBe("iam_root_mfa_enabled");
    expect(mfa.title).toBe("Ensure MFA is enabled for the root account");
    expect(mfa.severity).toBe("critical");
    expect(mfa.status).toBe("FAIL");
    expect(mfa.statusDetail).toBe("MFA is not enabled for root account.");
    expect(mfa.provider).toBe("aws");
    expect(mfa.account).toEqual({ uid: "123456789012", name: "retest-lab" });
    expect(mfa.region).toBe("global");
    expect(mfa.resource).toEqual({ uid: "arn:aws:iam::123456789012:root", name: "<root_account>", type: "AwsIamUser", group: "iam" });
    expect(mfa.risk.startsWith("The root account is the most privileged user")).toBe(true);
    expect(mfa.remediation.startsWith("Using IAM console navigate to Dashboard")).toBe(true);
    expect(mfa.references).toEqual([
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa",
      "https://docs.prowler.com/checks/aws/iam-policies/iam_9#cli-command",
    ]);
    expect(mfa.relatedUrl).toBe("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html");
    expect(mfa.compliance["CIS-3.0"]).toEqual(["1.5"]);
    expect(mfa.categories).toEqual([]);
    expect(mfa.time).toBe("2026-11-08T18:48:00.000000");
    expect(mfa.uid).toBe("prowler-aws-iam_root_mfa_enabled-123456789012-global-<root_account>");
    expect(mfa.product).toEqual({ name: "Prowler", version: "5.2.0" });
  });

  it("maps every severity word, and informational to info", () => {
    expect(checks.map((c) => c.severity)).toEqual(["critical", "high", "medium", "critical", "high", "critical", "high", "high", "high", "low"]);
    const parsed = JSON.parse(ocsf);
    parsed[0].severity = "Informational";
    expect(parseProwlerOcsf(JSON.stringify(parsed))[0]!.severity).toBe("info");
  });

  it("refuses anything that is not Prowler OCSF output", () => {
    expect(() => parseProwlerOcsf("x")).toThrow(/not JSON/);
    expect(() => parseProwlerOcsf("{}")).toThrow(/not Prowler OCSF output/);
    expect(() => parseProwlerOcsf('[{"message": "hello"}]')).toThrow(/not Prowler OCSF output/);
    expect(() => parseProwlerOcsf('[{"metadata": {"product": {"name": "Other"}, "event_code": "x"}, "status_code": "FAIL"}]')).toThrow(/not Prowler OCSF output/);
  });
});

describe("prowlerFindings", () => {
  const findings = prowlerFindings(parseProwlerOcsf(ocsf));

  it("makes one raw finding per failed check, and none for a pass or a manual check", () => {
    expect(findings).toHaveLength(7);
    expect(findings.map((f) => f.rawId)).toEqual([
      "iam_root_mfa_enabled",
      "iam_user_mfa_enabled_console_access",
      "s3_bucket_public_access",
      "s3_bucket_level_public_access_block",
      "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
      "cloudtrail_multi_region_enabled",
      "iam_avoid_root_usage",
    ]);
    for (const f of findings) {
      expect(f.tool).toBe("prowler");
      expect(f.phase).toBe("assessment");
      expect(f.cloud?.provider).toBe("aws");
      expect(f.cloud?.account).toBe("123456789012");
      expect(f.cloud?.accountName).toBe("retest-lab");
    }
  });

  it("places the finding on the account, with the resource as the scope", () => {
    const bucket = findings[2]!;
    expect(bucket.cloud).toEqual({
      provider: "aws",
      account: "123456789012",
      accountName: "retest-lab",
      region: "eu-west-3",
      resource: "arn:aws:s3:::juice-shop-uploads",
      resourceType: "AwsS3Bucket",
    });
    expect(bucket.scope).toBe("arn:aws:s3:::juice-shop-uploads");
    expect(bucket.title).toBe("S3 Bucket juice-shop-uploads has public access due to bucket ACL.");
  });

  it("keeps Prowler's severity, its risk text as the description, its remediation as the fix, no CWE of its own", () => {
    const sg = findings[4]!;
    expect(sg.severity).toBe("high");
    expect(sg.cwe).toEqual([]);
    expect(sg.cve).toEqual([]);
    expect(sg.description).toBe("Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to SSH port 22.\nIf Security groups are not properly configured the attack surface is increased.");
    expect(sg.fix?.startsWith("Apply Zero Trust approach.")).toBe(true);
    expect(sg.fix).toContain("\naws ec2 revoke-security-group-ingress");
    expect(sg.references).toEqual(["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"]);
    expect(sg.tags).toEqual(["aws", "ec2", "AwsEc2SecurityGroup", "internet-exposed", "cis-3.0:5.2"]);
    expect(sg.detectedAt).toBe("2026-11-08T18:48:00.000Z");
  });

  it("writes the evidence from the status detail and the resource", () => {
    const sg = findings[4]!;
    expect(sg.evidence).toEqual([
      {
        kind: "scanner-output",
        title: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 on lab-web",
        content: [
          "status: FAIL",
          "detail: Security group lab-web (sg-0f3a9c1d2e4b5a6c7) has SSH port 22 open to the Internet.",
          "resource: arn:aws:ec2:eu-west-3:123456789012:security-group/sg-0f3a9c1d2e4b5a6c7 (AwsEc2SecurityGroup)",
          "region: eu-west-3",
          "account: 123456789012 (retest-lab)",
        ].join("\n"),
      },
    ]);
  });
});

describe("parseProwler", () => {
  it("returns the failed checks as findings and counts the rest", () => {
    const r = parseProwler(ocsf);
    expect(r.tool).toBe("prowler");
    expect(r.findings).toHaveLength(7);
    expect(r.passed).toBe(2);
    expect(r.manual).toBe(1);
    expect(r.warnings).toEqual(["1 check needs a manual look: iam_securityaudit_role_created"]);
  });
});
