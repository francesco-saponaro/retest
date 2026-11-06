import { z } from "zod";

export const OWASP_TOP_10_2021_IDS = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"] as const;
export const OwaspTop10IdSchema = z.enum(OWASP_TOP_10_2021_IDS);
export type OwaspTop10Id = z.infer<typeof OwaspTop10IdSchema>;

export interface OwaspTop10Category {
  id: OwaspTop10Id;
  name: string;
  url: string;
}

/** OWASP Top 10, 2021 edition. https://owasp.org/Top10/ */
export const OWASP_TOP_10_2021: readonly OwaspTop10Category[] = [
  { id: "A01", name: "Broken Access Control", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  { id: "A02", name: "Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  { id: "A03", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  { id: "A04", name: "Insecure Design", url: "https://owasp.org/Top10/A04_2021-Insecure_Design/" },
  { id: "A05", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  {
    id: "A06",
    name: "Vulnerable and Outdated Components",
    url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  },
  {
    id: "A07",
    name: "Identification and Authentication Failures",
    url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
  },
  {
    id: "A08",
    name: "Software and Data Integrity Failures",
    url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
  },
  {
    id: "A09",
    name: "Security Logging and Monitoring Failures",
    url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
  },
  {
    id: "A10",
    name: "Server-Side Request Forgery",
    url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
  },
];

export function owaspTop10(id: string): OwaspTop10Category | undefined {
  return OWASP_TOP_10_2021.find((c) => c.id === id);
}
