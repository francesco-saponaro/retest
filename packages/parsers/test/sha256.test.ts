import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha256hex } from "../src/sha256.js";

const reference = (s: string) => createHash("sha256").update(s).digest("hex");

describe("sha256hex", () => {
  it("matches the platform's SHA-256 on the known vectors", () => {
    expect(sha256hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });

  it("agrees with node:crypto on the strings finding ids are made of, at every length around a block boundary", () => {
    const base = ["a-1b2c3d4e5f60", "nuclei", "http-missing-security-headers:content-security-policy", "asset-web-127-0-0-1-3000", "GET /"].join("\n");
    for (let n = 0; n <= 130; n += 1) {
      const s = base.slice(0, n) + "x".repeat(Math.max(0, n - base.length));
      expect(sha256hex(s)).toBe(reference(s));
    }
    expect(sha256hex("é — ü ∑ 🙂")).toBe(reference("é — ü ∑ 🙂"));
  });

  it("is what findingId uses, so ids are the same in Node and in the browser", async () => {
    const { findingId } = await import("../src/normalize.js");
    const id = findingId("a-1", { tool: "nmap", rawId: "port-3000-tcp" }, "asset-host-127-0-0-1", "3000/tcp");
    expect(id).toBe(`f-${reference(["a-1", "nmap", "port-3000-tcp", "asset-host-127-0-0-1", "3000/tcp"].join("\n")).slice(0, 12)}`);
  });
});
