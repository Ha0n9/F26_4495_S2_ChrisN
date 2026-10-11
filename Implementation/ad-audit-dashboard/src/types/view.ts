import type { DictionaryEntry } from './dictionary';
import type { Finding, Severity } from './scan';

/** A finding joined with its dictionary entry, ready to render. */
export interface FindingRow {
  key: string;
  finding: Finding;
  /** Undefined when the dictionary has no entry for this checkId. */
  entry?: DictionaryEntry;
  title: string;
  category: string;
  severity: Severity;
  objectCount: number;
}

export interface CoverageRow {
  key: string;
  checkId: string;
  name: string;
  status: 'Completed' | 'Failed' | 'Not run';
  errorMessage?: string;
  /** Null when the check did not complete, so the count is unknown. */
  findingCount: number | null;
}
