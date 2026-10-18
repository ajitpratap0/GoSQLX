export type Segment = { text: string; cls: string };

const TOKEN =
  /(\/\/.*$)|("(?:[^"\\]|\\.)*")|\b(package|import|func|if|for|range|return)\b|((?<=\bgosqlx\.|\bfunc )\w+)/g;

/**
 * Minimal Go syntax highlighter for the homepage API samples. Classes are the
 * design-token utilities (text-accent, text-brand, ...), so both themes work.
 */
export function highlightGoLine(line: string): Segment[] {
  const out: Segment[] = [];
  let last = 0;
  for (const match of line.matchAll(TOKEN)) {
    const index = match.index ?? 0;
    if (index > last) out.push({ text: line.slice(last, index), cls: 'text-fg-muted' });
    const [text, comment, str, keyword] = match;
    const cls = comment ? 'text-fg-subtle' : str ? 'text-brand' : keyword ? 'text-accent' : 'text-accent-warm';
    out.push({ text, cls });
    last = index + text.length;
  }
  if (last < line.length) out.push({ text: line.slice(last), cls: 'text-fg-muted' });
  return out;
}
