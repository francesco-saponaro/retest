import { signToken, RoleSchema } from "./auth.js";
import { config } from "./config.js";

/**
 * Mint a token: `pnpm -C apps/api token <user> [assessor|admin] [hours]`.
 * Needs RETEST_JWT_SECRET, the same one the API runs with. The token is printed and nothing is stored.
 */
const [, , sub, roleArg, hoursArg] = process.argv;
if (!sub) {
  console.error("usage: token <user> [assessor|admin] [hours]");
  process.exit(2);
}
const role = RoleSchema.parse(roleArg ?? "assessor");
const hours = Number(hoursArg ?? 24);
if (!Number.isFinite(hours) || hours <= 0) {
  console.error("hours must be a positive number");
  process.exit(2);
}
console.log(await signToken({ sub, role }, config().jwtSecret, { ttlSeconds: Math.round(hours * 3600) }));
