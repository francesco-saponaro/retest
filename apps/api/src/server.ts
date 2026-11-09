import { buildApp } from "./app.js";
import { config, openDatabase } from "./config.js";

const c = config();
const { db, close } = await openDatabase(c);
const app = await buildApp({
  db,
  jwtSecret: c.jwtSecret,
  logger: c.logger,
  rateLimit: { max: c.rateLimitMax, timeWindow: "1 minute" },
  importRateLimit: { max: c.importRateLimitMax, timeWindow: "1 minute" },
});

const stop = async () => {
  await app.close();
  await close();
  process.exit(0);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);

await app.listen({ port: c.port, host: c.host });
