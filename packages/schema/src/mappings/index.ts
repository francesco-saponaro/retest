export {
  OWASP_TOP_10_2021,
  OWASP_TOP_10_2021_IDS,
  OwaspTop10IdSchema,
  owaspTop10,
  type OwaspTop10Category,
  type OwaspTop10Id,
} from "./owasp-top10-2021.js";
export {
  OWASP_API_TOP_10_2023,
  OWASP_API_TOP_10_2023_IDS,
  OwaspApiTop10IdSchema,
  owaspApiTop10,
  type OwaspApiTop10Id,
  type OwaspApiTop10Risk,
} from "./owasp-api-2023.js";
export { ASVS_V4_CHAPTERS, ASVS_V4_CHAPTER_IDS, AsvsChapterIdSchema, asvsChapter, type AsvsChapter, type AsvsChapterId } from "./asvs-v4.js";
export { CIS_CONTROLS_V8, CisControlNumberSchema, cisControl, type CisControl, type CisControlNumber } from "./cis-v8.js";
export { knownCwes, lookupCwe, mappingsForOwaspTop10, type CategoryDefaults, type CweMapping } from "./cwe.js";
