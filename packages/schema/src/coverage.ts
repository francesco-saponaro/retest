import type { OwaspTop10Id } from "./mappings/owasp-top10-2021.js";
import { TOOLS, type Tool } from "./source.js";

/**
 * Which OWASP Top 10 2021 categories each tool looks for, the way the lab runs it. This is a coarse
 * judgement, not a promise: a tool on this list for a category has rules for some issues in it, not
 * for all of them. It is what lets a coverage matrix tell "looked and found nothing" from "nobody
 * looked".
 *
 * - Nmap with version detection and the vulners script: exposed services (A05) and versions with
 *   known CVEs (A06).
 * - Nuclei's community templates: exposed panels and files, weak TLS, some injection checks,
 *   misconfiguration, CVEs, default logins and SSRF.
 * - ZAP baseline is a passive scan: it reads responses and never sends an attack, so it sees headers,
 *   cookies, transport and old JavaScript libraries, and not injection.
 * - Semgrep reads the source: access checks, crypto, injection, insecure settings, auth code,
 *   unsafe deserialisation and SSRF patterns.
 * - Trivy on an image: packages with known CVEs, and nothing else.
 * - Prowler on a cloud account: public access, encryption, configuration, MFA and password
 *   policy, and logging.
 *
 * A04 Insecure Design is on no list: no scanner tests a design. It needs a person.
 */
export const TOOL_OWASP_TOP10: Readonly<Record<Exclude<Tool, "manual">, readonly OwaspTop10Id[]>> = {
  nmap: ["A05", "A06"],
  nuclei: ["A01", "A02", "A03", "A05", "A06", "A07", "A10"],
  zap: ["A01", "A02", "A05", "A06"],
  semgrep: ["A01", "A02", "A03", "A05", "A07", "A08", "A10"],
  trivy: ["A06"],
  prowler: ["A01", "A02", "A05", "A07", "A09"],
};

/** The tools among those that ran which look for this category, in the usual tool order. */
export function toolsThatLookFor(category: OwaspTop10Id, ran: readonly Tool[]): Tool[] {
  return TOOLS.filter((t) => t !== "manual" && ran.includes(t) && TOOL_OWASP_TOP10[t].includes(category));
}
