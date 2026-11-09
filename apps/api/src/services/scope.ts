import type { Asset, Scope } from "@retest/schema";

/**
 * Whether an asset is covered by the authorisation. A target can be a host or an address
 * (`127.0.0.1`, `shop.example.test`), an IPv4 network (`10.0.10.0/24`), a URL prefix
 * (`http://127.0.0.1:3000`), or a name as the tool spells it (a repository, an image, an account).
 * Exclusions use the same forms and win. Nothing here guesses: an asset no target matches is not
 * covered, and the import records it as out of scope and says so.
 */
export function coveredByScope(asset: Asset, scope: Scope): boolean {
  if (scope.exclusions.some((x) => matches(asset, x))) return false;
  return scope.targets.some((t) => matches(asset, t));
}

function matches(asset: Asset, target: string): boolean {
  const t = target.trim().toLowerCase();
  if (!t) return false;
  const name = asset.name.toLowerCase();
  // `retest-lab (aws 123456789012)` is covered by `aws 123456789012` and by `123456789012`.
  if (name === t || name.includes(`(${t})`) || name.split(/[\s()]+/).includes(t)) return true;
  if (asset.host) {
    const host = asset.host.toLowerCase();
    if (host === t) return true;
    const net = parseCidr(t);
    if (net && inNetwork(host, net)) return true;
  }
  if (asset.url) {
    const url = asset.url.toLowerCase();
    const prefix = t.replace(/\/+$/, "");
    if (url === prefix || url.startsWith(`${prefix}/`)) return true;
    try {
      const host = new URL(asset.url).hostname.toLowerCase();
      if (host === t) return true;
      const net = parseCidr(t);
      if (net && inNetwork(host, net)) return true;
    } catch {
      /* not a URL after all */
    }
  }
  return false;
}

interface Cidr {
  base: number;
  bits: number;
}

function ipv4(value: string): number | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!m) return undefined;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return undefined;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

function parseCidr(value: string): Cidr | undefined {
  const m = /^([\d.]+)\/(\d{1,2})$/.exec(value);
  if (!m) return undefined;
  const base = ipv4(m[1]!);
  const bits = Number(m[2]);
  if (base === undefined || bits > 32) return undefined;
  return { base, bits };
}

function inNetwork(host: string, net: Cidr): boolean {
  const ip = ipv4(host);
  if (ip === undefined) return false;
  const mask = net.bits === 0 ? 0 : (0xffffffff << (32 - net.bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((net.base & mask) >>> 0);
}
