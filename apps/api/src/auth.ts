import { SignJWT, errors, jwtVerify } from "jose";
import { z } from "zod";

/**
 * Who is calling. Tokens are HS256 JWTs signed with one shared secret: the API runs for one
 * team, there is no login screen, and a token is minted with `pnpm -C apps/api token <user>`.
 * `sub` is the user; everything that is owned is owned by a `sub`. `admin` can see every
 * assessment, `assessor` only their own.
 */
export const ROLES = ["assessor", "admin"] as const;
export const RoleSchema = z.enum(ROLES);
export type Role = z.infer<typeof RoleSchema>;

export interface Principal {
  sub: string;
  role: Role;
}

/** The token's own claims, checked after the signature. Unknown roles are refused, not defaulted. */
const ClaimsSchema = z.object({
  sub: z.string().min(1),
  role: RoleSchema.default("assessor"),
});

/** The only algorithm this API signs with, so the only one it accepts. */
const ALGORITHM = "HS256";
const MIN_SECRET_LENGTH = 32;

export class AuthError extends Error {
  override name = "AuthError";
}

function keyFrom(secret: string): Uint8Array {
  if (secret.length < MIN_SECRET_LENGTH) throw new AuthError(`the JWT secret must be at least ${MIN_SECRET_LENGTH} characters`);
  return new TextEncoder().encode(secret);
}

export interface SignOptions {
  /** Seconds until the token expires. A day by default. */
  ttlSeconds?: number;
  now?: Date;
}

export async function signToken(principal: { sub: string; role?: Role }, secret: string, options: SignOptions = {}): Promise<string> {
  const key = keyFrom(secret);
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const ttl = options.ttlSeconds ?? 24 * 60 * 60;
  return new SignJWT({ role: principal.role ?? "assessor" })
    .setProtectedHeader({ alg: ALGORITHM, typ: "JWT" })
    .setSubject(principal.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(key);
}

/**
 * Verify the signature with the one algorithm allowed, then the expiry, then the claims.
 * The `alg` in the token's header is input from the client and never decides anything here:
 * `none`, or a key-confusion attempt with RS256, fails before the payload is read.
 */
export async function verifyToken(token: string, secret: string): Promise<Principal> {
  const key = keyFrom(secret);
  let payload: unknown;
  try {
    ({ payload } = await jwtVerify(token, key, { algorithms: [ALGORITHM], requiredClaims: ["sub", "exp"] }));
  } catch (e) {
    if (e instanceof errors.JOSEError) throw new AuthError(e.code === "ERR_JWT_EXPIRED" ? "token expired" : "invalid token");
    throw e;
  }
  const claims = ClaimsSchema.safeParse(payload);
  if (!claims.success) throw new AuthError("invalid token claims");
  return { sub: claims.data.sub, role: claims.data.role };
}

/** The token in an `Authorization: Bearer …` header, or undefined when the header is not that. */
export function bearerToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const m = /^Bearer\s+(\S+)$/i.exec(header);
  return m?.[1];
}
