import { api, apiAvailable } from './api';
import type { FindingDictionary } from '@/types/dictionary';
import type { ScanResult } from '@/types/scan';

export const SCAN_PATH = 'data/scan-result.json';
export const DICTIONARY_PATH = 'data/finding-dictionary.json';

/** Major version this build understands. */
const SUPPORTED_MAJOR = 1;

export class DataError extends Error {}

function majorOf(schemaVersion: string): number {
  const major = Number.parseInt(String(schemaVersion).split('.')[0] ?? '', 10);
  return Number.isNaN(major) ? -1 : major;
}

function assertSupported(schemaVersion: string, what: string): void {
  const major = majorOf(schemaVersion);
  if (major === -1) {
    throw new DataError(`The ${what} has no readable schemaVersion.`);
  }
  if (major > SUPPORTED_MAJOR) {
    throw new DataError(
      `The ${what} uses schema version ${schemaVersion}, which this dashboard does not understand. Update the dashboard rather than reading it with the wrong reader.`,
    );
  }
}

export function parseScanResult(raw: unknown, origin: string): ScanResult {
  const candidate = raw as Partial<ScanResult>;
  if (!candidate || typeof candidate !== 'object' || !candidate.scan || !Array.isArray(candidate.findings)) {
    throw new DataError(`${origin} does not look like a scan result. It needs a scan section and a findings array.`);
  }
  assertSupported(candidate.schemaVersion ?? '', 'scan result');
  return candidate as ScanResult;
}

export function parseDictionary(raw: unknown, origin: string): FindingDictionary {
  const candidate = raw as Partial<FindingDictionary>;
  if (!candidate || typeof candidate !== 'object' || !candidate.entries) {
    throw new DataError(`${origin} does not look like a finding dictionary. It needs an entries object.`);
  }
  assertSupported(candidate.schemaVersion ?? '', 'finding dictionary');
  return candidate as FindingDictionary;
}

async function fetchJson(path: string): Promise<unknown> {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new DataError(`Could not read ${path} (HTTP ${response.status}).`);
  }
  return response.json();
}

/**
 * Load through the local API when the page has a token, and fall back to the
 * static files otherwise.
 *
 * The fallback is not dead weight. A scan result can be reviewed on a machine
 * that has no PowerShell and no domain, which is the normal case for anyone
 * reading somebody else's audit, and that reader should not need the server.
 */
export async function loadScanResult(): Promise<ScanResult> {
  if (apiAvailable) {
    return parseScanResult(await api.latestScan(), 'the local API');
  }
  return parseScanResult(await fetchJson(SCAN_PATH), SCAN_PATH);
}

export async function loadDictionary(): Promise<FindingDictionary> {
  if (apiAvailable) {
    return parseDictionary(await api.dictionary(), 'the local API');
  }
  return parseDictionary(await fetchJson(DICTIONARY_PATH), DICTIONARY_PATH);
}

export async function readJsonFile(file: File): Promise<unknown> {
  const text = await file.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new DataError(`${file.name} is not valid JSON.`);
  }
}
