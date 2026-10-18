/** Format a YYYY-MM-DD date as "Oct 18, 2026" (UTC, so it never shifts a day). */
export function formatArticleDate(iso: string): string {
  const d = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
}
