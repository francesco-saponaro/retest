import { describe, expect, it } from "vitest";
import { ASSET_KINDS, AssetSchema, assetLabel } from "../src/asset.js";

const host = {
  id: "asset-juice-shop-host",
  assessmentId: "assessment-lab",
  kind: "host",
  name: "127.0.0.1",
  host: "127.0.0.1",
};

describe("Asset", () => {
  it("lists the kinds of asset an assessment can hold", () => {
    expect(ASSET_KINDS).toEqual([
      "host",
      "service",
      "web-app",
      "api",
      "repository",
      "container-image",
      "cloud-account",
      "cloud-resource",
    ]);
  });

  it("parses a host and fills the defaults", () => {
    const a = AssetSchema.parse(host);
    expect(a.inScope).toBe(true);
    expect(a.tags).toEqual([]);
    expect(a.port).toBeUndefined();
  });

  it("parses a service with a port", () => {
    const a = AssetSchema.parse({ ...host, id: "asset-3000", kind: "service", name: "http on 3000", port: 3000 });
    expect(a.port).toBe(3000);
  });

  it("rejects a port outside 1 to 65535", () => {
    expect(AssetSchema.safeParse({ ...host, port: 0 }).success).toBe(false);
    expect(AssetSchema.safeParse({ ...host, port: 70000 }).success).toBe(false);
    expect(AssetSchema.safeParse({ ...host, port: 80.5 }).success).toBe(false);
  });

  it("requires a url for a web app or an API, and checks it", () => {
    expect(AssetSchema.safeParse({ ...host, kind: "web-app" }).success).toBe(false);
    expect(AssetSchema.safeParse({ ...host, kind: "web-app", url: "not a url" }).success).toBe(false);
    expect(AssetSchema.safeParse({ ...host, kind: "api", url: "http://127.0.0.1:3000/rest" }).success).toBe(true);
  });

  it("rejects an unknown kind and an empty name", () => {
    expect(AssetSchema.safeParse({ ...host, kind: "printer" }).success).toBe(false);
    expect(AssetSchema.safeParse({ ...host, name: "" }).success).toBe(false);
  });

  it("labels an asset for a table row", () => {
    expect(assetLabel(AssetSchema.parse(host))).toBe("127.0.0.1");
    expect(assetLabel(AssetSchema.parse({ ...host, kind: "service", name: "http", port: 3000 }))).toBe("127.0.0.1:3000 (http)");
    expect(
      assetLabel(AssetSchema.parse({ ...host, kind: "web-app", name: "Juice Shop", url: "http://127.0.0.1:3000/" })),
    ).toBe("Juice Shop (http://127.0.0.1:3000/)");
  });
});
