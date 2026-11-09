import { randomBytes } from "node:crypto";
import type { z } from "zod";

/** An error with the status it should be answered with. The message is safe to show to the client. */
export class HttpError extends Error {
  override name = "HttpError";
  constructor(
    public readonly status: number,
    message: string,
    public readonly issues?: Issue[],
  ) {
    super(message);
  }
}

export interface Issue {
  path: string;
  message: string;
}

/** Run a zod schema over input from the client. Fails with a 400 that names every field that is wrong. */
export function validate<S extends z.ZodType>(schema: S, value: unknown, what: string): z.output<S> {
  const r = schema.safeParse(value);
  if (r.success) return r.data;
  return invalid(what, r.error);
}

export function invalid(what: string, error: z.ZodError): never {
  throw new HttpError(400, `invalid ${what}`, issuesOf(error));
}

/** One issue per field. A key the schema does not know is reported under that key, so the client sees which one. */
export function issuesOf(error: z.ZodError): Issue[] {
  return error.issues.flatMap((i) => {
    const base = i.path.map(String);
    if (i.code === "unrecognized_keys") return i.keys.map((k) => ({ path: [...base, k].join("."), message: "unknown field" }));
    return [{ path: base.join("."), message: i.message }];
  });
}

export function notFound(what = "not found"): never {
  throw new HttpError(404, what);
}

/** `a-` and twelve hex digits from a secure random source: not guessable, not sequential. */
export function newId(prefix: string): string {
  return `${prefix}-${randomBytes(6).toString("hex")}`;
}
