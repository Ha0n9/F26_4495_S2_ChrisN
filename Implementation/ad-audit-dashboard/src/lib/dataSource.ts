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

/**
 * Thrown when a static file is simply not there yet, as opposed to being
 * present and unreadable. The caller can word those two cases differently,
 * because they ask the user to do different things.
 */
export class MissingFileError extends DataError {}

async function fetchJson(path: string): Promise<unknown> {
  const response = await fetch(path, { cache: 'no-store' });

  if (response.status === 404) {
    throw new MissingFileError(`There is no file at ${path} yet.`);
  }
  if (!response.ok) {
    throw new DataError(`Could not read ${path} (HTTP ${response.status}).`);
  }

  // A development server answers a request for a file that does not exist by
  // serving the application's own index.html with status 200, not a 404. Left
  // unchecked, that HTML reaches JSON.parse and the user is told their scan
  // file is corrupt, when the truth is that there is no scan file at all.
  //
  // Those are different problems. One is answered by running a scan, the other
  // by investigating a damaged file. Reporting the wrong one sends the user
  // looking in the wrong place, so the content type is checked before parsing.
  const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
  if (!contentType.includes('json')) {
    throw new MissingFileError(`There is no file at ${path} yet.`);
  }

  try {
    return await response.json();
  } catch {
    throw new DataError(`${path} is present but is not valid JSON.`);
  }
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
  try {
    return parseScanResult(await fetchJson(SCAN_PATH), SCAN_PATH);
  } catch (error) {
    if (error instanceof MissingFileError) {
      throw new MissingFileError(
        `No scan has been saved to ${SCAN_PATH} yet. Run a scan to produce one, or use "Open a scan file" to load a result from anywhere on this machine.`,
      );
    }
    throw error;
  }
}

export async function loadDictionary(): Promise<FindingDictionary> {
  if (apiAvailable) {
    return parseDictionary(await api.dictionary(), 'the local API');
  }
  try {
    return parseDictionary(await fetchJson(DICTIONARY_PATH), DICTIONARY_PATH);
  } catch (error) {
    if (error instanceof MissingFileError) {
      throw new MissingFileError(
        `The finding dictionary is missing from ${DICTIONARY_PATH}. Findings will be listed by check id until it is restored.`,
      );
    }
    throw error;
  }
}

export async function readJsonFile(file: File): Promise<unknown> {
  const text = await file.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new DataError(`${file.name} is not valid JSON.`);
  }
}