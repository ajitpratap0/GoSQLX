#!/usr/bin/env node
/**
 * Fails when a homepage dialect-card anchor (DialectShowcase.tsx) does not match
 * a heading slug in docs/SQL_COMPATIBILITY.md. Slugs are computed with
 * github-slugger over every heading, as rehype-slug does for the rendered page.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import GithubSlugger from 'github-slugger';

const websiteDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const doc = readFileSync(resolve(websiteDir, '..', 'docs', 'SQL_COMPATIBILITY.md'), 'utf8');
const tsx = readFileSync(resolve(websiteDir, 'src', 'components', 'home', 'DialectShowcase.tsx'), 'utf8');

const anchors = [...tsx.matchAll(/anchor:\s*'([^']+)'/g)].map((m) => m[1]);
if (anchors.length === 0) {
  console.error('no dialect anchors found in DialectShowcase.tsx');
  process.exit(1);
}

const slugger = new GithubSlugger();
const slugs = new Set();
let inFence = false;
for (const line of doc.split('\n')) {
  if (/^\s*(```|~~~)/.test(line)) {
    inFence = !inFence;
    continue;
  }
  const m = !inFence && /^#{1,6}\s+(.+)$/.exec(line);
  if (!m) continue;
  const text = m[1].replace(/\\([_*`])/g, '$1').replace(/[`*]/g, '').trim();
  slugs.add(slugger.slug(text));
}

const missing = anchors.filter((a) => !slugs.has(a));
if (missing.length > 0) {
  console.error(`dialect anchors missing from docs/SQL_COMPATIBILITY.md: ${missing.join(', ')}`);
  process.exit(1);
}
console.log(`dialect anchors ok (${anchors.length})`);
