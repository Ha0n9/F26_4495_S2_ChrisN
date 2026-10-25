import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';

dayjs.extend(utc);

/**
 * Formats an ISO timestamp from the scan result.
 *
 * The module writes every timestamp in UTC with a trailing Z. dayjs parses
 * that correctly but then renders in the viewer's local zone, so formatting
 * without .utc() and appending the word "UTC" produced a local time wearing
 * a UTC label: a scan at 14:02 UTC displayed as "07:02 UTC" in Vancouver.
 * Wrong by seven hours, and wrong in a way that looks right.
 *
 * It matters beyond tidiness. An administrator correlating a finding against
 * domain controller event logs works from these timestamps, and a report
 * read in one country about a domain in another has no shared clock other
 * than this one.
 */
export function formatTimestamp(iso?: string | null): string {
  if (!iso) return 'Never';
  const parsed = dayjs.utc(iso);
  return parsed.isValid() ? `${parsed.format('YYYY-MM-DD HH:mm')} UTC` : String(iso);
}

/** Same instant in the viewer's own zone, for anything shown alongside their clock. */
export function formatTimestampLocal(iso?: string | null): string {
  if (!iso) return 'Never';
  const parsed = dayjs(iso);
  return parsed.isValid() ? parsed.format('YYYY-MM-DD HH:mm') : String(iso);
}

/**
 * Turns an attribute key into a column heading: daysInactive becomes
 * "Days inactive".
 *
 * The earlier version capitalised the first character and then capitalised
 * the first character of the remainder as well, so minPasswordLength came
 * out as "MIn password length". Split the word, lowercase the whole thing,
 * then raise the first letter once.
 */
export function labelize(key: string): string {
  const words = key
    .replace(/([A-Z])/g, ' $1')
    .replace(/[_.]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}
