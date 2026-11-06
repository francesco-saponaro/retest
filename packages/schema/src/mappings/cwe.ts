import type { AsvsChapterId } from "./asvs-v4.js";
import type { CisControlNumber } from "./cis-v8.js";
import type { OwaspApiTop10Id } from "./owasp-api-2023.js";
import type { OwaspTop10Id } from "./owasp-top10-2021.js";

/**
 * Where a weakness lives in each standard. Scanners report a CWE far more often than an OWASP
 * category, so this is the table everything else hangs off.
 *
 * The OWASP Top 10 column follows the "List of Mapped CWEs" that each category page on owasp.org
 * publishes. The ASVS chapters and CIS controls are the defaults for that category (see
 * `mappingsForOwaspTop10`) unless an entry says otherwise, and those defaults are a judgement call:
 * a standard's chapter and a Top 10 category never line up exactly.
 *
 * The table is a working subset, not the full CWE list. Add an entry when a parser meets a CWE
 * that is missing.
 */

export interface CweMapping {
  cwe: number;
  name: string;
  owaspTop10?: OwaspTop10Id;
  owaspApi?: OwaspApiTop10Id;
  asvs: AsvsChapterId[];
  cis: CisControlNumber[];
}

export interface CategoryDefaults {
  asvs: AsvsChapterId[];
  cis: CisControlNumber[];
}

/** Which ASVS chapters and CIS controls usually cover an OWASP Top 10 category. */
const OWASP_DEFAULTS: Record<OwaspTop10Id, CategoryDefaults> = {
  A01: { asvs: ["V4"], cis: [6, 16] },
  A02: { asvs: ["V6", "V8", "V9"], cis: [3] },
  A03: { asvs: ["V5"], cis: [16] },
  A04: { asvs: ["V1", "V11"], cis: [16] },
  A05: { asvs: ["V14"], cis: [4] },
  A06: { asvs: ["V14"], cis: [2, 7] },
  A07: { asvs: ["V2", "V3"], cis: [5, 6] },
  A08: { asvs: ["V10", "V14"], cis: [2, 16] },
  A09: { asvs: ["V7"], cis: [8] },
  A10: { asvs: ["V12"], cis: [16] },
};

export function mappingsForOwaspTop10(id: OwaspTop10Id): CategoryDefaults {
  const d = OWASP_DEFAULTS[id];
  return { asvs: [...d.asvs], cis: [...d.cis] };
}

interface Entry {
  name: string;
  owaspTop10?: OwaspTop10Id;
  owaspApi?: OwaspApiTop10Id;
  asvs?: AsvsChapterId[];
  cis?: CisControlNumber[];
}

const CWE_ENTRIES: Record<number, Entry> = {
  // A01 Broken Access Control
  22: { name: "Path traversal", owaspTop10: "A01", asvs: ["V12"] },
  23: { name: "Relative path traversal", owaspTop10: "A01", asvs: ["V12"] },
  35: { name: "Path traversal: '.../...//'", owaspTop10: "A01", asvs: ["V12"] },
  59: { name: "Improper link resolution before file access", owaspTop10: "A01", asvs: ["V12"] },
  200: { name: "Exposure of sensitive information to an unauthorized actor", owaspTop10: "A01", asvs: ["V8"] },
  201: { name: "Insertion of sensitive information into sent data", owaspTop10: "A01", asvs: ["V8"] },
  219: { name: "Storage of file with sensitive data under web root", owaspTop10: "A01", asvs: ["V12"] },
  264: { name: "Permissions, privileges, and access controls", owaspTop10: "A01" },
  275: { name: "Permission issues", owaspTop10: "A01" },
  276: { name: "Incorrect default permissions", owaspTop10: "A01", cis: [4, 6] },
  284: { name: "Improper access control", owaspTop10: "A01", owaspApi: "API5" },
  285: { name: "Improper authorization", owaspTop10: "A01", owaspApi: "API5" },
  352: { name: "Cross-site request forgery", owaspTop10: "A01" },
  359: { name: "Exposure of private personal information", owaspTop10: "A01", asvs: ["V8"], cis: [3] },
  377: { name: "Insecure temporary file", owaspTop10: "A01", asvs: ["V12"] },
  425: { name: "Direct request (forced browsing)", owaspTop10: "A01", owaspApi: "API5" },
  441: { name: "Unintended proxy or intermediary (confused deputy)", owaspTop10: "A01" },
  497: { name: "Exposure of sensitive system information to an unauthorized control sphere", owaspTop10: "A01", asvs: ["V8"] },
  538: { name: "Insertion of sensitive information into externally accessible file", owaspTop10: "A01", asvs: ["V8"] },
  540: { name: "Inclusion of sensitive information in source code", owaspTop10: "A01", asvs: ["V8"], cis: [16] },
  548: { name: "Exposure of information through directory listing", owaspTop10: "A01", asvs: ["V14"], cis: [4] },
  552: { name: "Files or directories accessible to external parties", owaspTop10: "A01", asvs: ["V12"] },
  566: { name: "Authorization bypass through user-controlled SQL primary key", owaspTop10: "A01", owaspApi: "API1" },
  601: { name: "URL redirection to untrusted site (open redirect)", owaspTop10: "A01", asvs: ["V5"] },
  639: { name: "Authorization bypass through user-controlled key (IDOR)", owaspTop10: "A01", owaspApi: "API1" },
  651: { name: "Exposure of WSDL file containing sensitive information", owaspTop10: "A01", asvs: ["V13"] },
  668: { name: "Exposure of resource to wrong sphere", owaspTop10: "A01" },
  706: { name: "Use of incorrectly resolved name or reference", owaspTop10: "A01" },
  862: { name: "Missing authorization", owaspTop10: "A01", owaspApi: "API5" },
  863: { name: "Incorrect authorization", owaspTop10: "A01", owaspApi: "API1" },
  913: { name: "Improper control of dynamically managed code resources", owaspTop10: "A01", asvs: ["V5"] },
  922: { name: "Insecure storage of sensitive information", owaspTop10: "A01", asvs: ["V8"], cis: [3] },
  1275: { name: "Sensitive cookie with improper SameSite attribute", owaspTop10: "A01", asvs: ["V3"] },

  // A02 Cryptographic Failures
  261: { name: "Weak encoding for password", owaspTop10: "A02", asvs: ["V2", "V6"] },
  296: { name: "Improper following of a certificate's chain of trust", owaspTop10: "A02", asvs: ["V9"] },
  310: { name: "Cryptographic issues", owaspTop10: "A02" },
  319: { name: "Cleartext transmission of sensitive information", owaspTop10: "A02", asvs: ["V9"] },
  321: { name: "Use of hard-coded cryptographic key", owaspTop10: "A02", asvs: ["V6"], cis: [3, 16] },
  322: { name: "Key exchange without entity authentication", owaspTop10: "A02", asvs: ["V9"] },
  323: { name: "Reusing a nonce, key pair in encryption", owaspTop10: "A02", asvs: ["V6"] },
  324: { name: "Use of a key past its expiration date", owaspTop10: "A02", asvs: ["V6"] },
  325: { name: "Missing cryptographic step", owaspTop10: "A02", asvs: ["V6"] },
  326: { name: "Inadequate encryption strength", owaspTop10: "A02", asvs: ["V6", "V9"] },
  327: { name: "Use of a broken or risky cryptographic algorithm", owaspTop10: "A02", asvs: ["V6", "V9"] },
  328: { name: "Use of weak hash", owaspTop10: "A02", asvs: ["V6"] },
  329: { name: "Generation of predictable IV with CBC mode", owaspTop10: "A02", asvs: ["V6"] },
  330: { name: "Use of insufficiently random values", owaspTop10: "A02", asvs: ["V6"] },
  331: { name: "Insufficient entropy", owaspTop10: "A02", asvs: ["V6"] },
  335: { name: "Incorrect usage of seeds in pseudo-random number generator", owaspTop10: "A02", asvs: ["V6"] },
  336: { name: "Same seed in pseudo-random number generator", owaspTop10: "A02", asvs: ["V6"] },
  337: { name: "Predictable seed in pseudo-random number generator", owaspTop10: "A02", asvs: ["V6"] },
  338: { name: "Use of cryptographically weak pseudo-random number generator", owaspTop10: "A02", asvs: ["V6"] },
  340: { name: "Generation of predictable numbers or identifiers", owaspTop10: "A02", asvs: ["V6"] },
  347: { name: "Improper verification of cryptographic signature", owaspTop10: "A02", owaspApi: "API2", asvs: ["V3", "V6"] },
  523: { name: "Unprotected transport of credentials", owaspTop10: "A02", asvs: ["V9"] },
  720: { name: "OWASP Top Ten 2007 category A9 - insecure communications", owaspTop10: "A02", asvs: ["V9"] },
  757: { name: "Selection of less-secure algorithm during negotiation (algorithm downgrade)", owaspTop10: "A02", asvs: ["V9"] },
  759: { name: "Use of a one-way hash without a salt", owaspTop10: "A02", asvs: ["V2", "V6"] },
  760: { name: "Use of a one-way hash with a predictable salt", owaspTop10: "A02", asvs: ["V2", "V6"] },
  780: { name: "Use of RSA algorithm without OAEP", owaspTop10: "A02", asvs: ["V6"] },
  818: { name: "Insufficient transport layer protection", owaspTop10: "A02", asvs: ["V9"] },
  916: { name: "Use of password hash with insufficient computational effort", owaspTop10: "A02", asvs: ["V2", "V6"] },

  // A03 Injection
  20: { name: "Improper input validation", owaspTop10: "A03" },
  74: { name: "Improper neutralization of special elements in output (injection)", owaspTop10: "A03" },
  75: { name: "Failure to sanitize special elements into a different plane", owaspTop10: "A03" },
  77: { name: "Command injection", owaspTop10: "A03" },
  78: { name: "OS command injection", owaspTop10: "A03" },
  79: { name: "Cross-site scripting", owaspTop10: "A03" },
  80: { name: "Basic XSS (script-related HTML tags not neutralized)", owaspTop10: "A03" },
  83: { name: "Improper neutralization of script in attributes in a web page", owaspTop10: "A03" },
  87: { name: "Improper neutralization of alternate XSS syntax", owaspTop10: "A03" },
  88: { name: "Argument injection", owaspTop10: "A03" },
  89: { name: "SQL injection", owaspTop10: "A03" },
  90: { name: "LDAP injection", owaspTop10: "A03" },
  91: { name: "XML injection (blind XPath injection)", owaspTop10: "A03" },
  93: { name: "CRLF injection", owaspTop10: "A03" },
  94: { name: "Code injection", owaspTop10: "A03" },
  95: { name: "Eval injection", owaspTop10: "A03" },
  96: { name: "Static code injection", owaspTop10: "A03" },
  97: { name: "Server-side include injection", owaspTop10: "A03" },
  98: { name: "PHP remote file inclusion", owaspTop10: "A03" },
  99: { name: "Resource injection", owaspTop10: "A03" },
  100: { name: "Technology-specific input validation problems", owaspTop10: "A03" },
  113: { name: "HTTP response splitting", owaspTop10: "A03" },
  116: { name: "Improper encoding or escaping of output", owaspTop10: "A03" },
  138: { name: "Improper neutralization of special elements", owaspTop10: "A03" },
  184: { name: "Incomplete list of disallowed inputs", owaspTop10: "A03" },
  470: { name: "Unsafe reflection", owaspTop10: "A03" },
  471: { name: "Modification of assumed-immutable data", owaspTop10: "A03" },
  564: { name: "SQL injection: Hibernate", owaspTop10: "A03" },
  610: { name: "Externally controlled reference to a resource in another sphere", owaspTop10: "A03" },
  643: { name: "XPath injection", owaspTop10: "A03" },
  644: { name: "Improper neutralization of HTTP headers for scripting syntax", owaspTop10: "A03" },
  652: { name: "XQuery injection", owaspTop10: "A03" },
  917: { name: "Expression language injection", owaspTop10: "A03" },

  // A04 Insecure Design
  73: { name: "External control of file name or path", owaspTop10: "A04", asvs: ["V12"] },
  183: { name: "Permissive list of allowed inputs", owaspTop10: "A04", asvs: ["V5"] },
  209: { name: "Generation of error message containing sensitive information", owaspTop10: "A04", asvs: ["V7"] },
  213: { name: "Exposure of sensitive information due to incompatible policies", owaspTop10: "A04", asvs: ["V8"] },
  235: { name: "Improper handling of extra parameters", owaspTop10: "A04", asvs: ["V5"] },
  256: { name: "Plaintext storage of a password", owaspTop10: "A04", asvs: ["V2", "V6"], cis: [3] },
  257: { name: "Storing passwords in a recoverable format", owaspTop10: "A04", asvs: ["V2", "V6"], cis: [3] },
  266: { name: "Incorrect privilege assignment", owaspTop10: "A04", asvs: ["V4"], cis: [6] },
  269: { name: "Improper privilege management", owaspTop10: "A04", asvs: ["V4"], cis: [6] },
  280: { name: "Improper handling of insufficient permissions or privileges", owaspTop10: "A04", asvs: ["V4"] },
  311: { name: "Missing encryption of sensitive data", owaspTop10: "A04", asvs: ["V6", "V8"], cis: [3] },
  312: { name: "Cleartext storage of sensitive information", owaspTop10: "A04", asvs: ["V6", "V8"], cis: [3] },
  313: { name: "Cleartext storage in a file or on disk", owaspTop10: "A04", asvs: ["V6", "V8"], cis: [3] },
  316: { name: "Cleartext storage of sensitive information in memory", owaspTop10: "A04", asvs: ["V8"], cis: [3] },
  400: { name: "Uncontrolled resource consumption", owaspTop10: "A04", owaspApi: "API4", asvs: ["V11", "V13"] },
  419: { name: "Unprotected primary channel", owaspTop10: "A04" },
  430: { name: "Deployment of wrong handler", owaspTop10: "A04" },
  434: { name: "Unrestricted upload of file with dangerous type", owaspTop10: "A04", asvs: ["V12"] },
  444: { name: "HTTP request/response smuggling", owaspTop10: "A04", asvs: ["V14"] },
  451: { name: "User interface misrepresentation of critical information", owaspTop10: "A04" },
  472: { name: "External control of assumed-immutable web parameter", owaspTop10: "A04", asvs: ["V4", "V5"] },
  501: { name: "Trust boundary violation", owaspTop10: "A04" },
  522: { name: "Insufficiently protected credentials", owaspTop10: "A04", owaspApi: "API2", asvs: ["V2"], cis: [5] },
  525: { name: "Use of web browser cache containing sensitive information", owaspTop10: "A04", asvs: ["V8"] },
  539: { name: "Use of persistent cookies containing sensitive information", owaspTop10: "A04", asvs: ["V3", "V8"] },
  579: { name: "J2EE bad practices: non-serializable object stored in session", owaspTop10: "A04", asvs: ["V3"] },
  598: { name: "Use of GET request method with sensitive query strings", owaspTop10: "A04", asvs: ["V8"] },
  602: { name: "Client-side enforcement of server-side security", owaspTop10: "A04", asvs: ["V4"] },
  642: { name: "External control of critical state data", owaspTop10: "A04", asvs: ["V4"] },
  646: { name: "Reliance on file name or extension of externally-supplied file", owaspTop10: "A04", asvs: ["V12"] },
  650: { name: "Trusting HTTP permission methods on the server side", owaspTop10: "A04", asvs: ["V4"] },
  653: { name: "Improper isolation or compartmentalization", owaspTop10: "A04" },
  656: { name: "Reliance on security through obscurity", owaspTop10: "A04" },
  657: { name: "Violation of secure design principles", owaspTop10: "A04" },
  770: { name: "Allocation of resources without limits or throttling", owaspTop10: "A04", owaspApi: "API4", asvs: ["V11", "V13"] },
  799: { name: "Improper control of interaction frequency (no rate limiting)", owaspTop10: "A04", owaspApi: "API4", asvs: ["V11"] },
  807: { name: "Reliance on untrusted inputs in a security decision", owaspTop10: "A04", asvs: ["V4"] },
  840: { name: "Business logic errors", owaspTop10: "A04", owaspApi: "API6", asvs: ["V11"] },
  841: { name: "Improper enforcement of behavioral workflow", owaspTop10: "A04", owaspApi: "API6", asvs: ["V11"] },
  927: { name: "Use of implicit intent for sensitive communication", owaspTop10: "A04" },
  1021: { name: "Improper restriction of rendered UI layers or frames (clickjacking)", owaspTop10: "A04", asvs: ["V14"], cis: [4, 16] },
  1173: { name: "Improper use of validation framework", owaspTop10: "A04", asvs: ["V5"] },

  // A05 Security Misconfiguration
  2: { name: "7PK - environment", owaspTop10: "A05" },
  11: { name: "ASP.NET misconfiguration: creating debug binary", owaspTop10: "A05" },
  13: { name: "ASP.NET misconfiguration: password in configuration file", owaspTop10: "A05", cis: [3, 4] },
  15: { name: "External control of system or configuration setting", owaspTop10: "A05" },
  16: { name: "Configuration", owaspTop10: "A05", owaspApi: "API8" },
  260: { name: "Password in configuration file", owaspTop10: "A05", cis: [3, 4] },
  315: { name: "Cleartext storage of sensitive information in a cookie", owaspTop10: "A05", asvs: ["V3", "V8"] },
  520: { name: ".NET misconfiguration: use of impersonation", owaspTop10: "A05" },
  526: { name: "Cleartext storage of sensitive information in an environment variable", owaspTop10: "A05", asvs: ["V8"], cis: [3] },
  537: { name: "Java runtime error message containing sensitive information", owaspTop10: "A05", asvs: ["V7"] },
  541: { name: "Inclusion of sensitive information in an include file", owaspTop10: "A05", asvs: ["V8"] },
  547: { name: "Use of hard-coded, security-relevant constants", owaspTop10: "A05" },
  611: { name: "Improper restriction of XML external entity reference (XXE)", owaspTop10: "A05", owaspApi: "API8", asvs: ["V5", "V14"] },
  614: { name: "Sensitive cookie in HTTPS session without 'Secure' attribute", owaspTop10: "A05", asvs: ["V3"] },
  756: { name: "Missing custom error page", owaspTop10: "A05", asvs: ["V7", "V14"] },
  776: { name: "Improper restriction of recursive entity references in DTDs (XML entity expansion)", owaspTop10: "A05", asvs: ["V5"] },
  942: { name: "Permissive cross-domain policy with untrusted domains (CORS)", owaspTop10: "A05", owaspApi: "API8", asvs: ["V14"] },
  1004: { name: "Sensitive cookie without 'HttpOnly' flag", owaspTop10: "A05", asvs: ["V3"] },
  1032: { name: "OWASP Top Ten 2017 category A6 - security misconfiguration", owaspTop10: "A05", owaspApi: "API8" },
  1174: { name: "ASP.NET misconfiguration: improper model validation", owaspTop10: "A05" },

  // A06 Vulnerable and Outdated Components
  937: { name: "OWASP Top Ten 2013 category A9 - using components with known vulnerabilities", owaspTop10: "A06" },
  1035: { name: "OWASP Top Ten 2017 category A9 - using components with known vulnerabilities", owaspTop10: "A06" },
  1104: { name: "Use of unmaintained third party components", owaspTop10: "A06", owaspApi: "API10" },

  // A07 Identification and Authentication Failures
  255: { name: "Credentials management errors", owaspTop10: "A07", owaspApi: "API2" },
  259: { name: "Use of hard-coded password", owaspTop10: "A07", asvs: ["V2"], cis: [5, 16] },
  287: { name: "Improper authentication", owaspTop10: "A07", owaspApi: "API2" },
  288: { name: "Authentication bypass using an alternate path or channel", owaspTop10: "A07", owaspApi: "API2" },
  290: { name: "Authentication bypass by spoofing", owaspTop10: "A07", owaspApi: "API2" },
  294: { name: "Authentication bypass by capture-replay", owaspTop10: "A07", owaspApi: "API2" },
  295: { name: "Improper certificate validation", owaspTop10: "A07", asvs: ["V9"] },
  297: { name: "Improper validation of certificate with host mismatch", owaspTop10: "A07", asvs: ["V9"] },
  300: { name: "Channel accessible by non-endpoint (man in the middle)", owaspTop10: "A07", asvs: ["V9"] },
  302: { name: "Authentication bypass by assumed-immutable data", owaspTop10: "A07", owaspApi: "API2" },
  304: { name: "Missing critical step in authentication", owaspTop10: "A07", owaspApi: "API2" },
  306: { name: "Missing authentication for critical function", owaspTop10: "A07", owaspApi: "API2" },
  307: { name: "Improper restriction of excessive authentication attempts (brute force)", owaspTop10: "A07", owaspApi: "API2", asvs: ["V2"] },
  346: { name: "Origin validation error", owaspTop10: "A07" },
  384: { name: "Session fixation", owaspTop10: "A07", asvs: ["V3"] },
  521: { name: "Weak password requirements", owaspTop10: "A07", owaspApi: "API2", asvs: ["V2"] },
  613: { name: "Insufficient session expiration", owaspTop10: "A07", owaspApi: "API2", asvs: ["V3"] },
  620: { name: "Unverified password change", owaspTop10: "A07", owaspApi: "API2", asvs: ["V2"] },
  640: { name: "Weak password recovery mechanism for forgotten password", owaspTop10: "A07", owaspApi: "API2", asvs: ["V2"] },
  798: { name: "Use of hard-coded credentials", owaspTop10: "A07", asvs: ["V2"], cis: [5, 16] },
  940: { name: "Improper verification of source of a communication channel", owaspTop10: "A07" },
  1216: { name: "Lockout mechanism errors", owaspTop10: "A07", owaspApi: "API2", asvs: ["V2"] },

  // A08 Software and Data Integrity Failures
  345: { name: "Insufficient verification of data authenticity", owaspTop10: "A08" },
  353: { name: "Missing support for integrity check", owaspTop10: "A08" },
  426: { name: "Untrusted search path", owaspTop10: "A08" },
  494: { name: "Download of code without integrity check", owaspTop10: "A08" },
  502: { name: "Deserialization of untrusted data", owaspTop10: "A08", asvs: ["V5"] },
  565: { name: "Reliance on cookies without validation and integrity checking", owaspTop10: "A08", asvs: ["V3", "V4"] },
  784: { name: "Reliance on cookies without validation and integrity checking in a security decision", owaspTop10: "A08", asvs: ["V3", "V4"] },
  829: { name: "Inclusion of functionality from untrusted control sphere", owaspTop10: "A08" },
  830: { name: "Inclusion of web functionality from an untrusted source", owaspTop10: "A08" },
  915: { name: "Improperly controlled modification of dynamically-determined object attributes (mass assignment)", owaspTop10: "A08", owaspApi: "API3", asvs: ["V5"] },

  // A09 Security Logging and Monitoring Failures
  117: { name: "Improper output neutralization for logs (log injection)", owaspTop10: "A09" },
  223: { name: "Omission of security-relevant information", owaspTop10: "A09" },
  532: { name: "Insertion of sensitive information into log file", owaspTop10: "A09", asvs: ["V7", "V8"], cis: [3, 8] },
  778: { name: "Insufficient logging", owaspTop10: "A09" },

  // A10 Server-Side Request Forgery
  918: { name: "Server-side request forgery", owaspTop10: "A10", owaspApi: "API7" },
};

function toCweNumber(id: number | string): number | undefined {
  if (typeof id === "number") return Number.isInteger(id) && id > 0 ? id : undefined;
  const m = /^(?:cwe-)?(\d+)$/i.exec(id.trim());
  return m?.[1] ? Number(m[1]) : undefined;
}

/** Look a CWE up by number or by its `CWE-nnn` spelling. */
export function lookupCwe(id: number | string): CweMapping | undefined {
  const n = toCweNumber(id);
  if (n === undefined) return undefined;
  const entry = CWE_ENTRIES[n];
  if (!entry) return undefined;
  const defaults = entry.owaspTop10 ? OWASP_DEFAULTS[entry.owaspTop10] : { asvs: [], cis: [] };
  const mapping: CweMapping = {
    cwe: n,
    name: entry.name,
    asvs: [...(entry.asvs ?? defaults.asvs)],
    cis: [...(entry.cis ?? defaults.cis)],
  };
  if (entry.owaspTop10) mapping.owaspTop10 = entry.owaspTop10;
  if (entry.owaspApi) mapping.owaspApi = entry.owaspApi;
  return mapping;
}

/** Every CWE the table knows, ascending. */
export function knownCwes(): number[] {
  return Object.keys(CWE_ENTRIES)
    .map(Number)
    .sort((a, b) => a - b);
}
