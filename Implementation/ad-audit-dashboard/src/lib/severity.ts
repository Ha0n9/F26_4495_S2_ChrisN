import { SEVERITIES, type Severity } from '@/types/scan';

/** Tag colours come from the Ant Design preset palette, not custom values. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: 'red',
  High: 'volcano',
  Medium: 'gold',
  Low: 'blue',
  Info: 'default',
};

/** Points deducted from the security score per finding. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  Critical: 25,
  High: 15,
  Medium: 8,
  Low: 3,
  Info: 0,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
}
