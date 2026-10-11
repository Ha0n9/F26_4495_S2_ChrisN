import dayjs from 'dayjs';

export function formatTimestamp(iso?: string | null): string {
  if (!iso) return 'Never';
  const parsed = dayjs(iso);
  return parsed.isValid() ? `${parsed.format('YYYY-MM-DD HH:mm')} UTC` : String(iso);
}

/** Turns an attribute key into a column heading: daysInactive -> Days inactive. */
export function labelize(key: string): string {
  const spaced = key.replace(/([A-Z])/g, ' $1').replace(/[_.]/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).trim().toLowerCase().replace(/^./, (c) => c.toUpperCase());
}
