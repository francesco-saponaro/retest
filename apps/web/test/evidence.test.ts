import { describe, expect, it } from "vitest";
import { redactionLine, secretLines, splitRequestResponse } from "../src/lib/evidence.js";
import { cors, corsRequest, jwt } from "./findings.js";

describe("splitRequestResponse", () => {
  it("splits a capture at the blank line before the status line", () => {
    const parts = splitRequestResponse(corsRequest);
    expect(parts?.request.split("\n")[0]).toBe("GET /rest/products/search?q= HTTP/1.1");
    expect(parts?.request.endsWith("Accept: */*")).toBe(true);
    expect(parts?.response.split("\n")[0]).toBe("HTTP/1.1 200 OK");
    expect(parts?.response.endsWith('"name":"Apple Juice (1000ml)"}]}')).toBe(true);
  });

  it("copes with CRLF captures and gives null for anything that is not a request and a response", () => {
    const crlf = "GET / HTTP/1.1\r\nHost: a\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    expect(splitRequestResponse(crlf)).toEqual({ request: "GET / HTTP/1.1\r\nHost: a", response: "HTTP/1.1 204 No Content" });
    expect(splitRequestResponse("package: jsonwebtoken\ninstalled: 0.4.0")).toBeNull();
    expect(splitRequestResponse("GET / HTTP/1.1\nHost: a\n")).toBeNull();
  });
});

describe("secretLines", () => {
  it("points at the lines that carry a credential, by header name or by shape", () => {
    expect(secretLines(corsRequest)).toEqual([{ line: 4, why: "a Cookie header" }]);
    const text = ["GET /api HTTP/1.1", "Authorization: Bearer abc.def.ghi", "X-Api-Key: 12345", "", "HTTP/1.1 200 OK", "Set-Cookie: session=1; HttpOnly", "", "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "key=AKIAIOSFODNN7EXAMPLE"].join("\n");
    expect(secretLines(text)).toEqual([
      { line: 2, why: "an Authorization header" },
      { line: 3, why: "an X-Api-Key header" },
      { line: 6, why: "a Set-Cookie header" },
      { line: 8, why: "a JWT" },
      { line: 9, why: "an AWS access key id" },
    ]);
  });

  it("finds nothing in scanner output that carries none", () => {
    expect(secretLines(jwt.evidence[0]!.content)).toEqual([]);
    expect(secretLines("Cookies: none set\nauthorization-policy: strict")).toEqual([]);
  });
});

describe("redactionLine", () => {
  it("says how much of the evidence is fit for the report", () => {
    expect(redactionLine(jwt.evidence)).toBe("1 piece, not redacted: it stays out of the report until it is.");
    expect(redactionLine(cors.evidence)).toBe("2 pieces, 1 redacted; 1 carries a credential to remove.");
    expect(redactionLine(cors.evidence.map((e) => ({ ...e, redacted: true })))).toBe("2 pieces, all redacted.");
    expect(redactionLine([])).toBe("None yet: the proof is captured during validation.");
  });
});
