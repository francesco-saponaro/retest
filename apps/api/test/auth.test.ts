import { SignJWT, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { AuthError, signToken, verifyToken } from "../src/auth.js";

const secret = "a-test-secret-that-is-long-enough-to-be-allowed";

describe("tokens", () => {
  it("signs a token for a user and verifies it back", async () => {
    const token = await signToken({ sub: "francesco" }, secret);
    expect(token.split(".")).toHaveLength(3);
    const claims = await verifyToken(token, secret);
    expect(claims).toEqual({ sub: "francesco", role: "assessor" });
  });

  it("carries the admin role when it is given", async () => {
    const token = await signToken({ sub: "root", role: "admin" }, secret);
    expect((await verifyToken(token, secret)).role).toBe("admin");
  });

  it("refuses a secret shorter than 32 characters", async () => {
    await expect(signToken({ sub: "x" }, "short")).rejects.toThrow("at least 32");
  });

  it("refuses an expired token", async () => {
    const token = await signToken({ sub: "francesco" }, secret, { ttlSeconds: -10 });
    await expect(verifyToken(token, secret)).rejects.toThrow(AuthError);
  });

  it("refuses a token signed with another secret", async () => {
    const token = await signToken({ sub: "francesco" }, "another-secret-that-is-also-long-enough-yes");
    await expect(verifyToken(token, secret)).rejects.toThrow(AuthError);
  });

  it("refuses a token whose payload was edited", async () => {
    const token = await signToken({ sub: "francesco" }, secret);
    const [h, , s] = token.split(".") as [string, string, string];
    const payload = Buffer.from(JSON.stringify({ sub: "root", role: "admin", exp: 4102444800 })).toString("base64url");
    await expect(verifyToken(`${h}.${payload}.${s}`, secret)).rejects.toThrow(AuthError);
  });

  it("refuses alg none, whatever the payload says", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: "root", role: "admin", exp: 4102444800 })).toString("base64url");
    await expect(verifyToken(`${header}.${payload}.`, secret)).rejects.toThrow(AuthError);
  });

  it("refuses a token signed with RS256, even a valid one", async () => {
    const { privateKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({ role: "admin" }).setProtectedHeader({ alg: "RS256" }).setSubject("root").setExpirationTime("1h").sign(privateKey);
    await expect(verifyToken(token, secret)).rejects.toThrow(AuthError);
  });

  it("refuses a token with no subject or no expiry", async () => {
    const key = new TextEncoder().encode(secret);
    const noSub = await new SignJWT({}).setProtectedHeader({ alg: "HS256" }).setExpirationTime("1h").sign(key);
    const noExp = await new SignJWT({}).setProtectedHeader({ alg: "HS256" }).setSubject("francesco").sign(key);
    await expect(verifyToken(noSub, secret)).rejects.toThrow(AuthError);
    await expect(verifyToken(noExp, secret)).rejects.toThrow(AuthError);
  });

  it("refuses a role it does not know", async () => {
    const key = new TextEncoder().encode(secret);
    const token = await new SignJWT({ role: "superuser" }).setProtectedHeader({ alg: "HS256" }).setSubject("x").setExpirationTime("1h").sign(key);
    await expect(verifyToken(token, secret)).rejects.toThrow(AuthError);
  });
});
