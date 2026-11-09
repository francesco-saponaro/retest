import type { Asset } from "@retest/schema";
import { describe, expect, it } from "vitest";
import { coveredByScope } from "../src/services/scope.js";

const host = (h: string): Asset => ({ id: "x", assessmentId: "a", kind: "host", name: h, host: h, inScope: true, tags: [] });
const web = (url: string): Asset => ({ id: "x", assessmentId: "a", kind: "web-app", name: url, url, inScope: true, tags: [] });
const named = (kind: Asset["kind"], name: string): Asset => ({ id: "x", assessmentId: "a", kind, name, inScope: true, tags: [] });
const scope = (targets: string[], exclusions: string[] = []) => ({ targets, exclusions, authorizedBy: "me" });

describe("coveredByScope", () => {
  it("matches a host by address and by network", () => {
    expect(coveredByScope(host("10.0.10.11"), scope(["10.0.10.11"]))).toBe(true);
    expect(coveredByScope(host("10.0.10.11"), scope(["10.0.10.0/24"]))).toBe(true);
    expect(coveredByScope(host("10.0.11.11"), scope(["10.0.10.0/24"]))).toBe(false);
    expect(coveredByScope(host("10.0.10.11"), scope(["127.0.0.1"]))).toBe(false);
  });

  it("matches a web app by URL prefix and by its host", () => {
    expect(coveredByScope(web("http://127.0.0.1:3000"), scope(["http://127.0.0.1:3000"]))).toBe(true);
    expect(coveredByScope(web("http://127.0.0.1:3000"), scope(["http://127.0.0.1:3000/"]))).toBe(true);
    expect(coveredByScope(web("http://127.0.0.1:3000"), scope(["127.0.0.1"]))).toBe(true);
    expect(coveredByScope(web("http://127.0.0.1:3000"), scope(["127.0.0.0/8"]))).toBe(true);
    expect(coveredByScope(web("http://127.0.0.1:3000"), scope(["http://127.0.0.1:30"]))).toBe(false);
    expect(coveredByScope(web("http://127.0.0.1:3000"), scope(["http://127.0.0.1:8080"]))).toBe(false);
  });

  it("matches a repository, an image or an account by name, case-insensitively", () => {
    expect(coveredByScope(named("repository", "juice-shop"), scope(["Juice-Shop"]))).toBe(true);
    expect(coveredByScope(named("container-image", "bkimminich/juice-shop:v17.1.1"), scope(["bkimminich/juice-shop:v17.1.1"]))).toBe(true);
    expect(coveredByScope(named("cloud-account", "aws 123456789012"), scope(["aws 123456789012"]))).toBe(true);
    expect(coveredByScope(named("repository", "juice-shop"), scope(["juice"]))).toBe(false);
  });

  it("lets an exclusion win over a target", () => {
    expect(coveredByScope(host("10.0.10.1"), scope(["10.0.10.0/24"], ["10.0.10.1"]))).toBe(false);
    expect(coveredByScope(host("10.0.10.2"), scope(["10.0.10.0/24"], ["10.0.10.1"]))).toBe(true);
  });

  it("does not crash on a target that is not an address, a network or a URL", () => {
    expect(coveredByScope(host("10.0.10.1"), scope(["999.0.0.0/8", "not a target", "10.0.10.0/40"]))).toBe(false);
  });
});
