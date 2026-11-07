import type { ParseResult, RawEvidence, RawFinding } from "./raw.js";
import { attr, child, children, numAttr, parseXml, text, type XmlNode } from "./xml.js";

/**
 * Nmap's XML output (`-oX`). Nmap is a discovery tool: it tells you which hosts answer, which
 * ports are open, which service and version sit behind each one, and what its NSE scripts
 * found out. It does not rate anything, so nothing here carries a severity.
 */

export type PortState = "open" | "closed" | "filtered" | "unfiltered" | "open|filtered" | "closed|filtered";

/** What a script reported, as Nmap structures it: a list, or a map of named values and nested tables. */
export type ScriptValue = string | ScriptValues;
export type ScriptValues = ScriptValue[] | { [key: string]: ScriptValue };

export interface NmapScript {
  id: string;
  /** The text as `nmap` prints it on the terminal. */
  output: string;
  /** The same thing structured, when the script gives a structure. */
  values?: ScriptValues;
}

export interface NmapService {
  name: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  osType?: string;
  /** How Nmap decided: `table` (the port number), `probed` (it talked to the service). */
  method: string;
  /** 0 to 10. A `table` guess is 3; a probe that matched is 10. */
  confidence: number;
  cpes: string[];
}

export interface NmapPort {
  protocol: "tcp" | "udp" | "sctp";
  port: number;
  state: PortState;
  reason: string;
  service?: NmapService;
  scripts: NmapScript[];
}

export interface NmapHost {
  address: string;
  addressType: string;
  mac?: { address: string; vendor?: string };
  hostnames: string[];
  state: "up" | "down" | "unknown" | "skipped";
  ports: NmapPort[];
  /** The ports Nmap summarised instead of listing: "65531 closed ports". */
  extraPorts: { state: PortState; count: number }[];
  /** Scripts that ran against the host rather than one port. */
  scripts: NmapScript[];
  startedAt?: string;
  finishedAt?: string;
}

export interface NmapScan {
  scanner: string;
  version?: string;
  args?: string;
  startedAt?: string;
  finishedAt?: string;
  summary?: string;
  hostsUp: number;
  hostsTotal: number;
  hosts: NmapHost[];
}

const ARRAYS = ["host", "port", "script", "table", "elem", "hostname", "address", "cpe", "extraports", "hostscript"] as const;

/** Parse the XML into the scan structure. Throws on anything that is not an Nmap report. */
export function parseNmapXml(xml: string): NmapScan {
  const doc = parseXml(xml, ARRAYS);
  const run = doc && (doc["nmaprun"] as XmlNode | undefined);
  if (!run || typeof run !== "object" || attr(run, "scanner") !== "nmap") {
    throw new Error("not an Nmap XML report: expected an <nmaprun scanner=\"nmap\"> root element");
  }
  const finished = child(child(run, "runstats"), "finished");
  const hostsStat = child(child(run, "runstats"), "hosts");
  const hosts = children(run, "host").map(parseHost);
  return withoutUndefined({
    scanner: "nmap",
    version: attr(run, "version"),
    args: attr(run, "args"),
    startedAt: epoch(attr(run, "start")),
    finishedAt: epoch(attr(finished, "time")),
    summary: attr(finished, "summary"),
    hostsUp: numAttr(hostsStat, "up") ?? hosts.filter((h) => h.state === "up").length,
    hostsTotal: numAttr(hostsStat, "total") ?? hosts.length,
    hosts,
  });
}

function parseHost(node: XmlNode): NmapHost {
  const addresses = children(node, "address");
  const ip = addresses.find((a) => attr(a, "addrtype") !== "mac") ?? addresses[0];
  const mac = addresses.find((a) => attr(a, "addrtype") === "mac");
  const ports = child(node, "ports");
  const host: NmapHost = {
    address: attr(ip, "addr") ?? "",
    addressType: attr(ip, "addrtype") ?? "",
    hostnames: children(child(node, "hostnames"), "hostname")
      .map((h) => attr(h, "name"))
      .filter((n): n is string => n !== undefined),
    state: (attr(child(node, "status"), "state") as NmapHost["state"] | undefined) ?? "unknown",
    ports: children(ports, "port").map(parsePort),
    extraPorts: children(ports, "extraports").map((e) => ({
      state: (attr(e, "state") ?? "closed") as PortState,
      count: numAttr(e, "count") ?? 0,
    })),
    scripts: children(node, "hostscript").flatMap((hs) => children(hs, "script").map(parseScript)),
  };
  if (mac) host.mac = withoutUndefined({ address: attr(mac, "addr") ?? "", vendor: attr(mac, "vendor") });
  const startedAt = epoch(attr(node, "starttime"));
  const finishedAt = epoch(attr(node, "endtime"));
  if (startedAt) host.startedAt = startedAt;
  if (finishedAt) host.finishedAt = finishedAt;
  return host;
}

function parsePort(node: XmlNode): NmapPort {
  const state = child(node, "state");
  const service = child(node, "service");
  const port: NmapPort = {
    protocol: (attr(node, "protocol") ?? "tcp") as NmapPort["protocol"],
    port: numAttr(node, "portid") ?? 0,
    state: (attr(state, "state") ?? "unfiltered") as PortState,
    reason: attr(state, "reason") ?? "",
    scripts: children(node, "script").map(parseScript),
  };
  if (service) {
    port.service = withoutUndefined({
      name: attr(service, "name") ?? "unknown",
      product: attr(service, "product"),
      version: attr(service, "version"),
      extraInfo: attr(service, "extrainfo"),
      osType: attr(service, "ostype"),
      method: attr(service, "method") ?? "table",
      confidence: numAttr(service, "conf") ?? 0,
      cpes: children(service, "cpe").map(text),
    });
  }
  return port;
}

function parseScript(node: XmlNode): NmapScript {
  const script: NmapScript = { id: attr(node, "id") ?? "", output: attr(node, "output") ?? "" };
  const values = scriptValues(node);
  if (values !== undefined) script.values = values;
  return script;
}

/** `<elem>` and `<table>` children become a list when they have no keys and a map when they do. */
function scriptValues(node: XmlNode): ScriptValues | undefined {
  const elems = children(node, "elem");
  const tables = children(node, "table");
  if (elems.length === 0 && tables.length === 0) return undefined;
  const keyed = [...elems, ...tables].every((n) => attr(n, "key") !== undefined);
  if (keyed) {
    const out: { [key: string]: ScriptValue } = {};
    for (const e of elems) out[attr(e, "key")!] = text(e);
    for (const t of tables) out[attr(t, "key")!] = scriptValues(t) ?? [];
    return out;
  }
  return [...elems.map(text), ...tables.map((t) => scriptValues(t) ?? [])];
}

function epoch(seconds: string | undefined): string | undefined {
  if (seconds === undefined) return undefined;
  const n = Number(seconds);
  return Number.isFinite(n) ? new Date(n * 1000).toISOString() : undefined;
}

type Defined<T> = { [K in keyof T]: Exclude<T[K], undefined> };

/** Drop the keys that are undefined, so optional fields are absent rather than set to nothing. */
function withoutUndefined<T extends object>(obj: T): Defined<T> {
  for (const key of Object.keys(obj) as (keyof T)[]) if (obj[key] === undefined) delete obj[key];
  return obj as Defined<T>;
}

/** The port line as `nmap` prints it: `3000/tcp open  http  Node.js Express framework`. */
export function portLine(port: NmapPort): string {
  const s = port.service;
  const parts = [`${port.port}/${port.protocol}`, port.state, "", s?.name ?? "unknown"];
  const product = [s?.product, s?.version].filter(Boolean).join(" ");
  const extra = s?.extraInfo ? `(${s.extraInfo})` : "";
  const detail = [product, extra].filter(Boolean).join(" ");
  if (detail) parts.push("", detail);
  return parts.join(" ");
}

function productLabel(service: NmapService | undefined): string | undefined {
  const label = [service?.product, service?.version].filter(Boolean).join(" ");
  return label || undefined;
}

/**
 * Raw findings from a scan: one per open port (an inventory line, phase 2), one per `vulners`
 * CPE table (a version match, a candidate for phase 3) and one for SMB signing when the
 * `smb-security-mode` host script says it is off. A host that is down gives nothing, and a
 * port that is `open|filtered` is not open.
 */
export function nmapFindings(scan: NmapScan): RawFinding[] {
  const findings: RawFinding[] = [];
  const runTitle = scan.args ?? "nmap";
  for (const host of scan.hosts) {
    if (host.state !== "up") continue;
    const detectedAt = host.startedAt ?? scan.startedAt;
    const where = withoutUndefined({ host: host.address, hostname: host.hostnames[0], detectedAt });
    for (const port of host.ports) {
      if (port.state !== "open") continue;
      const id = `${port.protocol}/${port.port}`;
      const label = productLabel(port.service);
      const evidence: RawEvidence[] = [
        { kind: "scanner-output", title: runTitle, content: portLine(port) },
        ...port.scripts.map((s) => ({ kind: "command-output" as const, title: s.id, content: s.output })),
      ];
      findings.push({
        tool: "nmap",
        rawId: id,
        title: `${port.service?.name ?? "unknown"} on ${id}${label ? ` (${label})` : ""}`,
        ...where,
        port: port.port,
        protocol: port.protocol === "udp" ? "udp" : "tcp",
        scope: id,
        cwe: [],
        cve: [],
        references: [],
        evidence,
        tags: [port.service?.name ?? "unknown", ...(port.service?.cpes ?? [])],
        phase: "recon",
      });
      let n = 0;
      for (const script of port.scripts) {
        if (script.id !== "vulners" || !script.values || Array.isArray(script.values)) continue;
        for (const [cpe, rows] of Object.entries(script.values)) {
          n += 1;
          const entries = Array.isArray(rows) ? rows.filter(isRecord) : [];
          const cves = entries.filter((e) => e["type"] === "cve" && typeof e["id"] === "string");
          if (cves.length === 0) continue;
          const scores = cves.map((e) => Number(e["cvss"])).filter(Number.isFinite);
          const ids = cves.map((e) => e["id"] as string);
          findings.push({
            tool: "nmap",
            rawId: `${id}/vulners${n > 1 ? `/${n}` : ""}`,
            title: `Known CVEs for ${label ?? cpe} on ${id}`,
            ...where,
            port: port.port,
            protocol: port.protocol === "udp" ? "udp" : "tcp",
            scope: id,
            description: `vulners matched ${cves.length} CVE${cves.length === 1 ? "" : "s"} against ${cpe}.`,
            impact:
              `Version match only: Nmap read "${label ?? cpe}" from the banner and vulners listed the CVEs published ` +
              "for that version. A patched build can keep the same version string, so none of these is confirmed " +
              "until the installed package is checked on the host.",
            cwe: [],
            cve: ids,
            ...(scores.length > 0 ? { cvss: { score: Math.max(...scores) } } : {}),
            references: ids.map((c) => `https://vulners.com/cve/${c}`),
            evidence: [{ kind: "command-output", title: "vulners", content: script.output }],
            tags: ["vulners", cpe],
            phase: "assessment",
          });
        }
      }
    }
    for (const script of host.scripts) {
      if (script.id !== "smb-security-mode" || !script.values || Array.isArray(script.values)) continue;
      const signing = script.values["message_signing"];
      if (typeof signing !== "string" || !signing.startsWith("disabled")) continue;
      const smbPort = host.ports.find((p) => p.state === "open" && (p.port === 445 || p.port === 139))?.port ?? 445;
      findings.push({
        tool: "nmap",
        rawId: "smb-security-mode",
        title: "SMB signing not required",
        ...where,
        port: smbPort,
        protocol: "tcp",
        scope: `tcp/${smbPort}`,
        description: `smb-security-mode reports message_signing: ${signing}.`,
        impact:
          "Without mandatory signing, anyone on the network path can relay or alter SMB traffic to this host " +
          "(NTLM relay). Confirm the setting on the host before rating it.",
        cwe: [924],
        cve: [],
        references: ["https://nmap.org/nsedoc/scripts/smb-security-mode.html"],
        evidence: [{ kind: "command-output", title: "smb-security-mode", content: script.output }],
        tags: ["smb"],
        phase: "assessment",
      });
    }
  }
  return findings;
}

function isRecord(value: unknown): value is { [key: string]: ScriptValue } {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parse an Nmap XML report into raw findings. */
export function parseNmap(xml: string): ParseResult & { scan: NmapScan } {
  const scan = parseNmapXml(xml);
  const warnings: string[] = [];
  if (scan.hosts.length > 0 && scan.hostsUp === 0) warnings.push(`no host was up: ${scan.hostsTotal} scanned, 0 up`);
  return { tool: "nmap", scan, findings: nmapFindings(scan), warnings };
}
