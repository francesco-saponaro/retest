import { describe, expect, it } from "vitest";
import { EVIDENCE_KINDS, EvidenceSchema } from "../src/evidence.js";
import { SourceSchema, TOOLS } from "../src/source.js";

describe("Source", () => {
  it("lists the tools a finding can come from, plus manual work", () => {
    expect(TOOLS).toEqual(["nmap", "nuclei", "zap", "semgrep", "trivy", "prowler", "manual"]);
  });

  it("needs a tool and the tool's own id for the finding", () => {
    const s = SourceSchema.parse({ tool: "nuclei", rawId: "CVE-2021-3129" });
    expect(s).toEqual({ tool: "nuclei", rawId: "CVE-2021-3129" });
    expect(SourceSchema.safeParse({ tool: "burp", rawId: "1" }).success).toBe(false);
    expect(SourceSchema.safeParse({ tool: "zap" }).success).toBe(false);
  });

  it("can carry a reference link", () => {
    const s = SourceSchema.parse({ tool: "zap", rawId: "10021", reference: "https://www.zaproxy.org/docs/alerts/10021/" });
    expect(s.reference).toBe("https://www.zaproxy.org/docs/alerts/10021/");
    expect(SourceSchema.safeParse({ tool: "zap", rawId: "10021", reference: "zaproxy" }).success).toBe(false);
  });
});

describe("Evidence", () => {
  const base = {
    id: "ev-1",
    kind: "request-response",
    content: "GET /rest/user/whoami HTTP/1.1\nHost: 127.0.0.1:3000\n\nHTTP/1.1 200 OK",
  };

  it("lists the kinds of evidence", () => {
    expect(EVIDENCE_KINDS).toEqual(["request-response", "command-output", "scanner-output", "screenshot", "log", "note"]);
  });

  it("parses a request/response capture and marks it unredacted by default", () => {
    const e = EvidenceSchema.parse(base);
    expect(e.redacted).toBe(false);
    expect(e.findingId).toBeUndefined();
  });

  it("requires some content", () => {
    expect(EvidenceSchema.safeParse({ ...base, content: "" }).success).toBe(false);
  });

  it("checks the capture time is an ISO date and the source is a known tool", () => {
    expect(EvidenceSchema.safeParse({ ...base, capturedAt: "2026-11-06T18:00:00Z" }).success).toBe(true);
    expect(EvidenceSchema.safeParse({ ...base, capturedAt: "yesterday" }).success).toBe(false);
    expect(EvidenceSchema.safeParse({ ...base, source: { tool: "nmap", rawId: "3000/tcp" } }).success).toBe(true);
    expect(EvidenceSchema.safeParse({ ...base, source: { tool: "nessus", rawId: "1" } }).success).toBe(false);
  });
});
