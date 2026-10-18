#!/usr/bin/env node
// Regression guard for technical SEO (#767). Run after `next build`:
//   npm run check:seo
// Walks the prerendered HTML in .next/server/app and fails when a page has a
// <title> over 60 characters, a meta description outside 70-160 characters, no
// JSON-LD, no theme-color, no manifest link or no RSS autodiscovery link.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '../.next/server/app');
const TITLE_MAX = 60;
const DESC_MIN = 70;
const DESC_MAX = 160;

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.name.endsWith('.html')) yield p;
  }
}

function decode(s) {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'");
}

if (!fs.existsSync(ROOT)) {
  console.error('check-seo: .next/server/app not found; run `npm run build` first.');
  process.exit(2);
}

const problems = [];
let pages = 0;
for (const file of walk(ROOT)) {
  const html = fs.readFileSync(file, 'utf-8');
  // Skip framework shells (404, error) that are not indexable pages.
  if (/<meta name="robots" content="noindex/.test(html)) continue;
  if (/^(_not-found|_global-error|404|500)/.test(path.relative(ROOT, file))) continue;
  pages++;
  const rel = path.relative(ROOT, file);
  const title = /<title>([\s\S]*?)<\/title>/.exec(html);
  const desc = /<meta name="description" content="([^"]*)"/.exec(html);
  if (!title) problems.push(`${rel}: missing <title>`);
  else if (decode(title[1]).length > TITLE_MAX) problems.push(`${rel}: title is ${decode(title[1]).length} chars (max ${TITLE_MAX}): ${decode(title[1])}`);
  if (!desc) problems.push(`${rel}: missing meta description`);
  else {
    const n = decode(desc[1]).length;
    if (n < DESC_MIN || n > DESC_MAX) problems.push(`${rel}: description is ${n} chars (want ${DESC_MIN}-${DESC_MAX})`);
  }
  if (!html.includes('application/ld+json')) problems.push(`${rel}: no JSON-LD`);
  if (!/<meta name="theme-color"/.test(html)) problems.push(`${rel}: no theme-color meta`);
  if (!/<link rel="manifest"/.test(html)) problems.push(`${rel}: no manifest link`);
  if (!/type="application\/rss\+xml"/.test(html)) problems.push(`${rel}: no RSS autodiscovery link`);
}

if (problems.length) {
  console.error(`check-seo: ${problems.length} problem(s) across ${pages} pages`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`check-seo: ${pages} pages OK`);
