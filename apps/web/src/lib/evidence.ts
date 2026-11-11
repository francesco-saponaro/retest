import type { Evidence, EvidenceKind } from "@retest/schema";
import { count } from "./format.js";

export const EVIDENCE_KIND_LABELS: Record<EvidenceKind, string> = {
  "request-response": "Request and response",
  "command-output": "Command output",
  "scanner-output": "Scanner output",
  screenshot: "Screenshot",
  log: "Log",
  note: "Note",
};

/**
 * A capture holds the request, a blank line, then the response, which starts with its status line.
 * Split there so the two can be read side by side. Anything else (scanner output, a command's
 * output) is shown whole: null.
 */
export function splitRequestResponse(content: string): { request: string; response: string } | null {
  const m = /\r?\n(?:\r?\n)+(?=HTTP\/\d)/.exec(content);
  if (!m) return null;
  const request = content.slice(0, m.index).replace(/\s+$/, "");
  const response = content.slice(m.index + m[0].length).replace(/\s+$/, "");
  if (!request || !response) return null;
  return { request, response };
}

export interface SecretLine {
  /** 1-based, as a person counts lines. */
  line: number;
  why: string;
}

/** Headers whose value is a credential or a session: these never go in a report as captured. */
const SECRET_HEADERS = ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "api-key", "x-amz-security-token"];

const HEADER_NAMES: Record<string, string> = {
  authorization: "an Authorization header",
  "proxy-authorization": "a Proxy-Authorization header",
  cookie: "a Cookie header",
  "set-cookie": "a Set-Cookie header",
  "x-api-key": "an X-Api-Key header",
  "x-auth-token": "an X-Auth-Token header",
  "api-key": "an Api-Key header",
  "x-amz-security-token": "an X-Amz-Security-Token header",
};

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/;
const AWS_KEY = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/;

/**
 * The lines of a capture that carry a credential: by header name (a Cookie, an Authorization) or
 * by shape (a JWT, an AWS access key id). It cannot find every secret; it finds the common ones so
 * the viewer can point at them before the evidence is marked redacted.
 */
export function secretLines(content: string): SecretLine[] {
  const out: SecretLine[] = [];
  content.split(/\r?\n/).forEach((text, i) => {
    const header = /^([A-Za-z][A-Za-z0-9-]*):\s/.exec(text)?.[1]?.toLowerCase();
    if (header && SECRET_HEADERS.includes(header)) {
      out.push({ line: i + 1, why: HEADER_NAMES[header] ?? `a ${header} header` });
    } else if (JWT.test(text)) {
      out.push({ line: i + 1, why: "a JWT" });
    } else if (AWS_KEY.test(text)) {
      out.push({ line: i + 1, why: "an AWS access key id" });
    }
  });
  return out;
}

/** The Evidence row of the seven fields: how much there is, and how much of it is fit for the report. */
export function redactionLine(evidence: readonly Pick<Evidence, "redacted" | "content">[]): string {
  if (evidence.length === 0) return "None yet: the proof is captured during validation.";
  const pieces = count(evidence.length, "piece");
  const redacted = evidence.filter((e) => e.redacted).length;
  const secrets = evidence.filter((e) => !e.redacted && secretLines(e.content).length > 0).length;
  if (redacted === evidence.length) return `${pieces}, all redacted.`;
  const stays = evidence.length === 1 ? ": it stays out of the report until it is." : ": they stay out of the report until they are.";
  const tail = secrets > 0 ? `; ${secrets} ${secrets === 1 ? "carries" : "carry"} a credential to remove.` : redacted === 0 ? stays : ".";
  const state = redacted === 0 ? (evidence.length === 1 ? "not redacted" : "none redacted") : `${redacted} redacted`;
  return `${pieces}, ${state}${tail}`;
}
