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
 * Builds the coverage table.
 *
 * Three outcomes, not two. A check that failed is not the same as one that
 * found nothing, and a check that ran but stopped short of part of its ground
 * is neither. Collapsing that third case into "Completed" is how a group
 * hierarchy the tool never finished walking was presented as examined.
 */
export function buildCoverageRows(scan: ScanResult, dictionary: FindingDictionary): CoverageRow[] {
  const { checksRequested, checksCompleted, checksFailed } = scan.scan;
  const checksPartial = scan.scan.checksPartial ?? [];

  return checksRequested.map((checkId) => {
    const failure = checksFailed.find((f) => f.checkId === checkId);
    const completed = checksCompleted.includes(checkId);

    // A check may truncate in more than one place, so every reason is kept.
    const truncations = checksPartial.filter((p) => p.checkId === checkId);

    const status: CoverageRow['status'] = failure
      ? 'Failed'
      : !completed
        ? 'Not run'
        : truncations.length > 0
          ? 'Partial'
          : 'Completed';

    return {
      key: checkId,
      checkId,
      name: dictionary.entries[checkId]?.technicalName ?? checkId,
      status,
      errorMessage: failure?.errorMessage,
      partialReason: truncations.length > 0 ? truncations.map((p) => p.reason).join(' ') : undefined,
      // The count is what this check did find. It is not a claim that there
      // was nothing else to find, which is what the status column is for.
      findingCount: completed ? scan.findings.filter((f) => f.checkId === checkId).length : null,
    };
  });
}
