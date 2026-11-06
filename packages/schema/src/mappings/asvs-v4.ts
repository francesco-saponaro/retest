import { z } from "zod";

export const ASVS_V4_CHAPTER_IDS = [
  "V1",
  "V2",
  "V3",
  "V4",
  "V5",
  "V6",
  "V7",
  "V8",
  "V9",
  "V10",
  "V11",
  "V12",
  "V13",
  "V14",
] as const;
export const AsvsChapterIdSchema = z.enum(ASVS_V4_CHAPTER_IDS);
export type AsvsChapterId = z.infer<typeof AsvsChapterIdSchema>;

export interface AsvsChapter {
  id: AsvsChapterId;
  name: string;
}

/** OWASP Application Security Verification Standard 4.0.3, the fourteen chapters. https://github.com/OWASP/ASVS/tree/v4.0.3 */
export const ASVS_V4_CHAPTERS: readonly AsvsChapter[] = [
  { id: "V1", name: "Architecture, Design and Threat Modeling" },
  { id: "V2", name: "Authentication" },
  { id: "V3", name: "Session Management" },
  { id: "V4", name: "Access Control" },
  { id: "V5", name: "Validation, Sanitization and Encoding" },
  { id: "V6", name: "Stored Cryptography" },
  { id: "V7", name: "Error Handling and Logging" },
  { id: "V8", name: "Data Protection" },
  { id: "V9", name: "Communication" },
  { id: "V10", name: "Malicious Code" },
  { id: "V11", name: "Business Logic" },
  { id: "V12", name: "Files and Resources" },
  { id: "V13", name: "API and Web Service" },
  { id: "V14", name: "Configuration" },
];

export function asvsChapter(id: string): AsvsChapter | undefined {
  return ASVS_V4_CHAPTERS.find((c) => c.id === id);
}
