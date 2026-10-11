import type { FindingDictionary } from '@/types/dictionary';
import type { ScanResult } from '@/types/scan';
import type { CoverageRow, FindingRow } from '@/types/view';
import { compareSeverity } from './severity';

/**
 * Joins findings to dictionary entries on checkId.
 *
 * A finding whose checkId is missing from the dictionary is still rendered,
 * using the checkId as its title. Findings are never hidden because the
 * content layer is incomplete.
 */
export function buildFindingRows(scan: ScanResult, dictionary: FindingDictionary): FindingRow[] {
  return scan.findings
    .map((finding) => {
      const entry = dictionary.entries[finding.checkId];
      return {
        key: finding.findingId || finding.checkId,
        finding,
        entry,
        title: entry?.title ?? finding.checkId,
        category: entry?.category ?? 'Uncategorized',
        severity: finding.severity ?? entry?.defaultSeverity ?? 'Info',
        objectCount: finding.affectedObjectCount ?? finding.affectedObjects.length,
      };
    })
    .sort((a, b) => compareSeverity(a.severity, b.severity));
}

/**
 * Builds the coverage table. A check that failed is not the same as a check
 * that found nothing, so findingCount is null for anything that did not run.
 */
export function buildCoverageRows(scan: ScanResult, dictionary: FindingDictionary): CoverageRow[] {
  const { checksRequested, checksCompleted, checksFailed } = scan.scan;

  return checksRequested.map((checkId) => {
    const failure = checksFailed.find((f) => f.checkId === checkId);
    const completed = checksCompleted.includes(checkId);

    return {
      key: checkId,
      checkId,
      name: dictionary.entries[checkId]?.technicalName ?? checkId,
      status: failure ? 'Failed' : completed ? 'Completed' : 'Not run',
      errorMessage: failure?.errorMessage,
      findingCount: completed ? scan.findings.filter((f) => f.checkId === checkId).length : null,
    };
  });
}
