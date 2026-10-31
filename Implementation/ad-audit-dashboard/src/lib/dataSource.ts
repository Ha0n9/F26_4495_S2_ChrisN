import { api, tokenPresent } from './api';
import { DataError, MissingFileError } from './errors';
import { validateDictionary, validateScanResult } from './validate';
import type { FindingDictionary } from '@/types/dictionary';
import type { ScanResult } from '@/types/scan';

export { DataError, MissingFileError };

export const SCAN_PATH = 'data/scan-result.json';
export const DICTIONARY_PATH = 'data/finding-dictionary.json';

/**
 * Every scan result entering the dashboard passes through here, whatever
 * route it arrived by: the static file, the local API, or a file the reader
 * opened by hand. Validating at one boundary is the only way to be sure a
 * malformed result cannot reach the renderer, and the API is not a trusted
 * source simply because it is local. It reads a file from disk that anything
 * on the machine could have written.
 */
export function parseScanResult(raw: unknown, origin: string): ScanResult {
  return validateScanResult(raw, origin);
}

export function parseDictionary(raw: unknown, origin: string): FindingDictionary {
  return validateDictionary(raw, origin);
}

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
 * Load through the local API when the page holds a token, and fall back to the
 * static files otherwise.
 *
 * The fallback is not dead weight. A scan result can be reviewed on a machine
 * that has no PowerShell and no domain, which is the normal case for anyone
 * reading somebody else's audit, and that reader should not need the server.
 *
 * The token is checked at call time rather than at module load, because the
 * server rejecting it is a normal event: it issues a new one every restart.
 * A module constant captured at load would keep calling an API this page can
 * no longer reach.
 */
export async function loadScanResult(): Promise<ScanResult> {
  if (tokenPresent()) {
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
  if (tokenPresent()) {
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
    return JSON.parse(text.replace(/^﻿/, ''));
  } catch {
    throw new DataError(`${file.name} is not valid JSON.`);
  }
}
