/**
 * Shape of finding-dictionary.json.
 *
 * Hand written content, versioned in the repository. It describes check
 * types in plain language. It never contains scan data.
 */

import type { Severity } from './scan';

export interface DictionaryReference {
  label: string;
  url: string;
}

export interface DictionaryEntry {
  /** Name a security specialist would use. */
  technicalName: string;
  /** Name a generalist administrator would understand. Shown as the finding title. */
  title: string;
  category: string;
  defaultSeverity: Severity;
  whyItMatters: string;
  whatToDo: string[];
  /** Heading for the first column of the affected objects table. */
  objectColumnLabel: string;
  /** Which attribute keys to promote into table columns. */
  keyAttributes: string[];
  references: DictionaryReference[];
}

export interface FindingDictionary {
  schemaVersion: string;
  language: string;
  severityScale: Severity[];
  entries: Record<string, DictionaryEntry>;
}
