import { SEVERITY_WEIGHT } from './severity';
import type { Finding } from '@/types/scan';

/**
 * The score is computed here rather than in the PowerShell module, so the
 * module stays free of presentation logic. Changing the weighting never
 * requires a new scan.
 */
export function securityScore(findings: Finding[]): number {
  const deducted = findings.reduce((total, f) => total + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
  return Math.max(0, Math.round(100 - deducted));
}

export function scoreStatus(score: number): 'exception' | 'normal' | 'success' {
  if (score < 50) return 'exception';
  if (score < 80) return 'normal';
  return 'success';
}
