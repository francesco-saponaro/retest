/**
 * The bearer token for the API, kept for this tab only. Minted on the command line with
 * `pnpm -C apps/api token <user>`; there is no login. Session storage goes when the tab closes,
 * and nothing here survives a reload of the browser profile.
 */
const KEY = "retest.token";

function storage(): Storage | null {
  try {
    return globalThis.sessionStorage ?? null;
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return storage()?.getItem(KEY) ?? null;
}

export function setToken(token: string): void {
  storage()?.setItem(KEY, token);
}

export function clearToken(): void {
  storage()?.removeItem(KEY);
}

export function hasToken(): boolean {
  return getToken() !== null;
}
