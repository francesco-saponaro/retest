import { z } from "zod";

export const CisControlNumberSchema = z.number().int().min(1).max(18);
export type CisControlNumber = z.infer<typeof CisControlNumberSchema>;

export interface CisControl {
  number: CisControlNumber;
  name: string;
}

/** CIS Critical Security Controls, version 8, the eighteen controls. https://www.cisecurity.org/controls/v8 */
export const CIS_CONTROLS_V8: readonly CisControl[] = [
  { number: 1, name: "Inventory and Control of Enterprise Assets" },
  { number: 2, name: "Inventory and Control of Software Assets" },
  { number: 3, name: "Data Protection" },
  { number: 4, name: "Secure Configuration of Enterprise Assets and Software" },
  { number: 5, name: "Account Management" },
  { number: 6, name: "Access Control Management" },
  { number: 7, name: "Continuous Vulnerability Management" },
  { number: 8, name: "Audit Log Management" },
  { number: 9, name: "Email and Web Browser Protections" },
  { number: 10, name: "Malware Defenses" },
  { number: 11, name: "Data Recovery" },
  { number: 12, name: "Network Infrastructure Management" },
  { number: 13, name: "Network Monitoring and Defense" },
  { number: 14, name: "Security Awareness and Skills Training" },
  { number: 15, name: "Service Provider Management" },
  { number: 16, name: "Application Software Security" },
  { number: 17, name: "Incident Response Management" },
  { number: 18, name: "Penetration Testing" },
];

export function cisControl(n: number): CisControl | undefined {
  return CIS_CONTROLS_V8.find((c) => c.number === n);
}
