import { AssetSchema, FindingSchema, type Asset, type Evidence, type Finding, type Source } from "@retest/schema";
import type { RawFinding } from "./raw.js";
import { sha256hex } from "./sha256.js";

/** What goes in the impact field until someone has validated the finding and written the real one. */
export const UNASSESSED_IMPACT = "Not assessed yet. The scanner reported this; the impact is written after validation.";

/** What goes in the fix field until the finding is validated and a fix is decided. */
export const UNWRITTEN_FIX = "Not written yet. The fix is decided after validation.";

export interface NormalizeOptions {
  assessmentId: string;
  /** Assets that already exist. A raw finding that lands on one of them reuses it instead of making a new one. */
  assets?: Asset[];
  /** The time to stamp on the findings. Defaults to now. */
  now?: Date;
}

export interface Normalized {
  findings: Finding[];
  /** Every asset the findings point at: the ones given that were used, and the ones made here. */
  assets: Asset[];
}

const TITLE_MAX = 200;
const SCOPE_MAX = 500;

/**
 * Turn raw findings into findings in the Retest format.
 *
 * Each raw finding is placed on an asset (a host for a port, a web app for a URL), gets a
 * deterministic id from what it is and where it is (so importing the same file twice gives the
 * same ids), and has its seven fields filled: what the tool knows goes in, what it cannot know
 * gets a placeholder that says so. Severity is the tool's own or `info`; the tool's CVSS claim
 * is kept on the source, and the finding's own CVSS and its mappings to the standards are left
 * for `classify()`, which checks the claim first.
 */
export function normalize(raw: RawFinding[], options: NormalizeOptions): Normalized {
  const now = (options.now ?? new Date()).toISOString();
  const assets = new AssetBook(options.assessmentId, options.assets ?? []);
  const findings = raw.map((r) => {
    const asset = assets.place(r);
    const scope = cut(r.scope, SCOPE_MAX);
    const id = findingId(options.assessmentId, r, asset.id, scope);
    const source: Source = { tool: r.tool, rawId: r.rawId };
    if (r.references[0]) source.reference = r.references[0];
    if (r.severity) source.severity = r.severity;
    if (r.cvss && (r.cvss.vector || r.cvss.score !== undefined)) {
      source.cvss = { ...(r.cvss.vector ? { vector: r.cvss.vector } : {}), ...(r.cvss.score !== undefined ? { score: r.cvss.score } : {}) };
    }
    const evidence: Evidence[] = r.evidence.map((e, i) => ({
      id: `${id}-e${i + 1}`,
      findingId: id,
      kind: e.kind,
      ...(e.title ? { title: cut(e.title, TITLE_MAX) } : {}),
      content: e.content,
      redacted: false,
      ...(r.detectedAt ? { capturedAt: r.detectedAt } : {}),
      source: { tool: r.tool, rawId: r.rawId },
    }));
    return FindingSchema.parse({
      id,
      assessmentId: options.assessmentId,
      title: cut(r.title, TITLE_MAX),
      assetId: asset.id,
      scope,
      impact: r.impact ?? UNASSESSED_IMPACT,
      evidence,
      risk: { severity: r.severity ?? "info" },
      fix: r.fix ?? UNWRITTEN_FIX,
      phase: r.phase ?? "assessment",
      status: "open",
      sources: [source],
      mappings: { cwe: [...new Set(r.cwe)], cve: [...new Set(r.cve.map(canonicalCve).filter((c): c is string => c !== undefined))], owaspTop10: [], owaspApi: [], asvs: [], cis: [] },
      createdAt: now,
      updatedAt: now,
    });
  });
  return { findings, assets: assets.used() };
}

/** `f-` and twelve hex digits of a hash over what identifies the finding. */
export function findingId(assessmentId: string, raw: Pick<RawFinding, "tool" | "rawId">, assetId: string, scope: string): string {
  const digest = sha256hex([assessmentId, raw.tool, raw.rawId, assetId, scope].join("\n"));
  return `f-${digest.slice(0, 12)}`;
}

/** `cve-2015-9235` becomes `CVE-2015-9235`; anything that is not a CVE id is dropped. */
function canonicalCve(id: string): string | undefined {
  const m = /^\s*cve-(\d{4})-(\d{4,})\s*$/i.exec(id);
  return m ? `CVE-${m[1]}-${m[2]}` : undefined;
}

function cut(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

/** Finds or makes the asset a raw finding belongs on, and remembers which ones were used. */
class AssetBook {
  private readonly known: Asset[];
  private readonly touched = new Map<string, Asset>();

  constructor(
    private readonly assessmentId: string,
    existing: Asset[],
  ) {
    this.known = [...existing];
  }

  /** A URL wins over a host (a web finding on a known host is about the web app), then the host, then the other kinds. */
  place(raw: RawFinding): Asset {
    const origin = raw.url ? originOf(raw.url) : undefined;
    const asset = origin
      ? this.webApp(origin)
      : raw.host
        ? this.host(raw)
        : raw.repository
          ? this.repository(raw.repository)
          : raw.image
            ? this.image(raw.image)
            : raw.cloud
              ? this.cloudAccount(raw.cloud)
              : undefined;
    if (!asset) throw new Error(`cannot place "${raw.title}" (${raw.tool} ${raw.rawId}): it has no host, url, repository, image or cloud account`);
    this.touched.set(asset.id, asset);
    return asset;
  }

  used(): Asset[] {
    return [...this.touched.values()];
  }

  private webApp(origin: URL): Asset {
    const url = origin.origin;
    const found = this.known.find((a) => (a.kind === "web-app" || a.kind === "api") && a.url && sameOrigin(a.url, url));
    if (found) return found;
    const host = origin.hostname;
    const port = origin.port ? Number(origin.port) : origin.protocol === "https:" ? 443 : 80;
    return this.remember(
      AssetSchema.parse({
        id: `asset-web-${slug(host)}-${port}`,
        assessmentId: this.assessmentId,
        kind: "web-app",
        name: `${host}:${port}`,
        host,
        port,
        url,
      }),
    );
  }

  private host(raw: RawFinding): Asset {
    const address = raw.host!;
    const found = this.known.find((a) => a.kind === "host" && a.host === address);
    if (found) return found;
    return this.remember(
      AssetSchema.parse({
        id: `asset-host-${slug(address)}`,
        assessmentId: this.assessmentId,
        kind: "host",
        name: raw.hostname ?? address,
        host: address,
      }),
    );
  }

  private repository(name: string): Asset {
    const found = this.known.find((a) => a.kind === "repository" && a.name === name);
    if (found) return found;
    return this.remember(AssetSchema.parse({ id: `asset-repo-${slug(name)}`, assessmentId: this.assessmentId, kind: "repository", name }));
  }

  private image(name: string): Asset {
    const found = this.known.find((a) => a.kind === "container-image" && a.name === name);
    if (found) return found;
    return this.remember(AssetSchema.parse({ id: `asset-image-${slug(name)}`, assessmentId: this.assessmentId, kind: "container-image", name }));
  }

  private cloudAccount(cloud: NonNullable<RawFinding["cloud"]>): Asset {
    const found = this.known.find((a) => a.kind === "cloud-account" && a.tags.includes(cloud.provider) && a.name.includes(cloud.account));
    if (found) return found;
    return this.remember(
      AssetSchema.parse({
        id: `asset-cloud-${slug(cloud.provider)}-${slug(cloud.account)}`,
        assessmentId: this.assessmentId,
        kind: "cloud-account",
        name: cloud.accountName ? `${cloud.accountName} (${cloud.provider} ${cloud.account})` : `${cloud.provider} ${cloud.account}`,
        tags: [cloud.provider],
      }),
    );
  }

  private remember(asset: Asset): Asset {
    this.known.push(asset);
    return asset;
  }
}

function originOf(url: string): URL | undefined {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u : undefined;
  } catch {
    return undefined;
  }
}

function sameOrigin(a: string, b: string): boolean {
  const ua = originOf(a);
  const ub = originOf(b);
  return ua !== undefined && ub !== undefined && ua.origin === ub.origin;
}
