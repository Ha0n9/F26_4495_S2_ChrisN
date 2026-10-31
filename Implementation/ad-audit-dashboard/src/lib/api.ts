import type { FindingDictionary } from '@/types/dictionary';
import type { ScanResult } from '@/types/scan';

/**
 * Client for the local API.
 *
 * The API runs on the same machine and requires a token that it prints when
 * it starts. The token arrives in the dashboard URL as a query parameter,
 * which the launcher prints as a ready made link.
 *
 * It is read once and kept in memory rather than in localStorage, because a
 * token that outlives the server process it belongs to is a token sitting in
 * browser storage for no reason. Restarting the server issues a new one, and
 * the old one stops working.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly detail?: string;

  constructor(message: string, status: number, detail?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

const STORAGE_KEY = 'adAudit.token';

/**
 * sessionStorage rather than localStorage.
 *
 * The token is only valid for the life of one server process, so storage that
 * outlives the tab would keep handing back a token that stopped working the
 * moment somebody restarted the server. sessionStorage is scoped to this tab
 * and cleared when it closes, which is as close as the browser gets to the
 * token's real lifetime.
 *
 * Every access is wrapped: storage throws rather than returning null in a
 * private window, and under some site-data settings it is absent entirely.
 * The page has to work either way, falling back to the in-memory token for
 * this page view only.
 */
function readStored(): string | null {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStored(value: string): void {
  try {
    window.sessionStorage.setItem(STORAGE_KEY, value);
  } catch {
    // Not fatal. The token stays in memory for this page view.
  }
}

function removeStored(): void {
  try {
    window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do.
  }
}

/**
 * A token in the URL always wins.
 *
 * Restarting the server prints a new link, and somebody who opens that link
 * in a tab holding an older token expects the new one to take effect. Reading
 * storage first would silently keep using the dead token and report the
 * server as unreachable.
 */
function readToken(): string | null {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get('token');
    if (fromUrl) {
      writeStored(fromUrl);
      // Take it out of the address bar so it is not left in the browser
      // history or copied by accident when somebody shares the URL.
      const clean = new URL(window.location.href);
      clean.searchParams.delete('token');
      window.history.replaceState({}, '', clean.toString());
      return fromUrl;
    }
  } catch {
    // A malformed URL is not worth failing over; fall through to storage.
  }
  return readStored();
}

let token = readToken();

/**
 * True when this page view has a token, so the API is worth calling.
 *
 * It is a snapshot taken at load. Once the server rejects the token, the
 * token is discarded and this no longer reflects reality, so the component
 * tree tracks that in state rather than re-reading this value. `tokenPresent`
 * exposes the live answer for anything that needs it.
 */
export const apiAvailable = token !== null;

export function tokenPresent(): boolean {
  return token !== null;
}

/**
 * Forgets the token, here and in storage.
 *
 * Called when the server rejects it, which happens on every server restart,
 * because the token is regenerated each time. Leaving the dead token in
 * storage would make a refresh look like it still had access and fail again.
 */
export function clearToken(): void {
  token = null;
  removeStored();
}

const RESTART_HINT =
  'The server issues a new token every time it starts. Open the link printed in its console again.';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!token) {
    throw new ApiError(
      'This page was opened without an access token, so it cannot reach the local API.',
      401,
      'Start the server and open the link it prints, which carries the token.',
    );
  }

  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: {
        'X-Audit-Token': token,
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        ...init?.headers,
      },
    });
  } catch (error) {
    throw new ApiError(
      'The local API is not responding.',
      0,
      `Check that the server is running. ${(error as Error).message}`,
    );
  }

  if (!response.ok) {
    let message = `The API returned ${response.status}.`;
    let detail: string | undefined;
    try {
      const body = await response.json();
      message = body.error ?? message;
      detail = body.detail ?? body.hint;
    } catch {
      // Not JSON. Keep the status message.
    }

    // A rejected token is almost always a restarted server rather than an
    // attack, and the recovery is specific enough to say outright. The token
    // is dropped here so a refresh shows the honest "no access" state rather
    // than failing the same way again.
    if (response.status === 401) {
      clearToken();
      throw new ApiError(
        'The local API no longer accepts this page’s access token.',
        401,
        detail ?? RESTART_HINT,
      );
    }

    throw new ApiError(message, response.status, detail);
  }

  return (await response.json()) as T;
}

export interface HealthResponse {
  ok: boolean;
  modulePath: string;
  moduleFound: boolean;
  scanOutputPath: string;
  platform: string;
}

export interface ScanResponse {
  result: ScanResult;
  durationMs: number;
  warnings: string[];
}

export interface ScanRequest {
  domainName?: string;
  newAccountGraceDays?: number;
}

export const api = {
  health: () => request<HealthResponse>('/api/health'),
  dictionary: () => request<FindingDictionary>('/api/dictionary'),
  latestScan: () => request<ScanResult>('/api/scan/latest'),
  runScan: (options: ScanRequest = {}) =>
    request<ScanResponse>('/api/scan', { method: 'POST', body: JSON.stringify(options) }),
};
