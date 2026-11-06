import { z } from "zod";

export const OWASP_API_TOP_10_2023_IDS = [
  "API1",
  "API2",
  "API3",
  "API4",
  "API5",
  "API6",
  "API7",
  "API8",
  "API9",
  "API10",
] as const;
export const OwaspApiTop10IdSchema = z.enum(OWASP_API_TOP_10_2023_IDS);
export type OwaspApiTop10Id = z.infer<typeof OwaspApiTop10IdSchema>;

export interface OwaspApiTop10Risk {
  id: OwaspApiTop10Id;
  name: string;
  url: string;
}

const base = "https://owasp.org/API-Security/editions/2023/en/";

/** OWASP API Security Top 10, 2023 edition. https://owasp.org/API-Security/editions/2023/en/0x11-t10/ */
export const OWASP_API_TOP_10_2023: readonly OwaspApiTop10Risk[] = [
  { id: "API1", name: "Broken Object Level Authorization", url: `${base}0xa1-broken-object-level-authorization/` },
  { id: "API2", name: "Broken Authentication", url: `${base}0xa2-broken-authentication/` },
  {
    id: "API3",
    name: "Broken Object Property Level Authorization",
    url: `${base}0xa3-broken-object-property-level-authorization/`,
  },
  { id: "API4", name: "Unrestricted Resource Consumption", url: `${base}0xa4-unrestricted-resource-consumption/` },
  { id: "API5", name: "Broken Function Level Authorization", url: `${base}0xa5-broken-function-level-authorization/` },
  {
    id: "API6",
    name: "Unrestricted Access to Sensitive Business Flows",
    url: `${base}0xa6-unrestricted-access-to-sensitive-business-flows/`,
  },
  { id: "API7", name: "Server Side Request Forgery", url: `${base}0xa7-server-side-request-forgery/` },
  { id: "API8", name: "Security Misconfiguration", url: `${base}0xa8-security-misconfiguration/` },
  { id: "API9", name: "Improper Inventory Management", url: `${base}0xa9-improper-inventory-management/` },
  { id: "API10", name: "Unsafe Consumption of APIs", url: `${base}0xaa-unsafe-consumption-of-apis/` },
];

export function owaspApiTop10(id: string): OwaspApiTop10Risk | undefined {
  return OWASP_API_TOP_10_2023.find((c) => c.id === id);
}
