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

function readToken(): string | null {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get('token');
    if (fromUrl) {
      // Take it out of the address bar so it is not left in the browser
      // history or copied by accident when somebody shares the URL.
      const clean = new URL(window.location.href);
      clean.searchParams.delete('token');
      window.history.replaceState({}, '', clean.toString());
      return fromUrl;
    }
  } catch {
    // A malformed URL is not worth failing over; the caller handles a null.
  }
  return null;
}

const token = readToken();

/** True when the page was opened with a token, so the API is usable. */
export const apiAvailable = token !== null;

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
