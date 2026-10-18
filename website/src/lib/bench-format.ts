/** v0.0.0-20261015143638-7193401b6746 -> v0.0.0-…7193401b (full version stays in go.mod). */
export function shortVersion(v: string): string {
  const m = /^(v\d+\.\d+\.\d+)-(?:[0-9a-z.]+\.)?\d{14}-([0-9a-f]{12})$/.exec(v);
  return m ? `${m[1]}-…${m[2].slice(0, 8)}` : v;
}

/** Keep the dialect cell to one short line: drop long parenthetical notes. */
export function shortDialect(d: string): string {
  const i = d.indexOf(' (');
  return i > 0 && d.length - i > 12 ? d.slice(0, i) : d;
}
