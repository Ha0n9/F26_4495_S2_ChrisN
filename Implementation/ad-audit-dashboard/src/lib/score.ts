import { SEVERITY_WEIGHT } from './severity';
import type { ScanResult } from '@/types/scan';

/**
 * The score is computed here rather than in the PowerShell module, so the
 * module stays free of presentation logic and the weighting can change
 * without re-running a scan against a live domain.
 *
 * It takes the whole scan, not just the findings, because a score computed
 * over findings alone is dishonest. A scan where every check failed produces
 * zero findings, and zero findings minus nothing is 100: a perfect score for
 * a domain the tool never managed to look at. That is precisely the failure
 * this project argues against everywhere else, so the score has to know how
 * much ground was actually covered.
 */

export interface ScoreResult {
  /** Null when nothing was examined. There is no score, not a score of 100. */
  value: number | null;
  checksCompleted: number;
  checksRequested: number;
  /** 0 to 1. How much of the requested ground the score is based on. */
  coverage: number;
  /**
   * True when the score is a partial view: some checks did not run, or some
   * ran without seeing everything. Both make the number an upper bound, and
   * the caption has to say so.
   */
  partial: boolean;
  /** Checks that ran to the end but examined only part of their ground. */
  checksTruncated: number;
}

export function securityScore(scan: ScanResult): ScoreResult {
  const requested = scan.scan.checksRequested.length;
  const completed = scan.scan.checksCompleted.length;
  const coverage = requested === 0 ? 0 : completed / requested;

  // Absent on scans written before truncation was reported, so default it
  // rather than letting an older file crash the summary.
  const truncated = scan.scan.checksPartial?.length ?? 0;

  if (completed === 0) {
    return {
      value: null,
      checksCompleted: 0,
      checksRequested: requested,
      coverage: 0,
      partial: true,
      checksTruncated: truncated,
    };
  }

  const deducted = scan.findings.reduce((total, f) => total + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);

  return {
    value: Math.max(0, Math.round(100 - deducted)),
    checksCompleted: completed,
    checksRequested: requested,
    coverage,
    // A truncated check counts towards completion but not towards coverage of
    // the domain, so the score it feeds is still partial.
    partial: completed < requested || truncated > 0,
    checksTruncated: truncated,
  };
}

export function scoreStatus(score: number | null): 'exception' | 'normal' | 'success' {
  if (score === null) return 'exception';
  if (score < 50) return 'exception';
  if (score < 80) return 'normal';
  return 'success';
}

/** Short caption stating what the number is based on. */
export function scoreCaption(result: ScoreResult): string {
  if (result.value === null) {
    return 'No checks completed, so no score can be given';
  }
  const missing = result.checksRequested - result.checksCompleted;

  if (missing > 0 && result.checksTruncated > 0) {
    return `Based on ${result.checksCompleted} of ${result.checksRequested} checks, ${result.checksTruncated} of which examined only part of the domain`;
  }
  if (missing > 0) {
    return `Based on ${result.checksCompleted} of ${result.checksRequested} checks`;
  }
  if (result.checksTruncated > 0) {
    return `All ${result.checksRequested} checks ran, but ${result.checksTruncated} examined only part of the domain`;
  }
  return `All ${result.checksRequested} checks completed`;
}
