#!/usr/bin/env node
/**
 * Static regression guard for docs layout fixes (#652, #655, #656).
 * Asserts: html scroll-padding-top, TOC rail scroll container with focus-ring
 * room, and skip-link z-index above the fixed Navbar's z-50.
 *
 * Usage: node scripts/check-layout-guards.mjs
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../src');
const read = (p) => readFileSync(resolve(root, p), 'utf8');
const failures = [];
const check = (ok, msg) => {
  if (!ok) failures.push(msg);
};

const css = read('app/globals.css');
check(
  /html\s*\{[^}]*scroll-padding-top:\s*5rem/.test(css),
  'globals.css: html must set scroll-padding-top: 5rem (anchor headings clear the fixed header)',
);

check(
  /@media\s*\(max-width:\s*1023\.98px\)\s*\{\s*html:has\(#docs-sidebar\)\s*\{[^}]*scroll-padding-top:\s*(7\.5|[89]|\d{2,})rem/.test(css),
  'globals.css: below lg, html:has(#docs-sidebar) needs scroll-padding-top >= 7.5rem (header 4rem + sticky Docs menu bar + margin)',
);
check(
  !/\.prose\s+(pre|table)[^{]*\{[^}]*content-visibility/.test(css),
  'globals.css: .prose pre/table must not use content-visibility (layout shifts break anchor jumps)',
);
check(
  /#main-content:focus-visible\s*\{[^}]*outline:\s*none/.test(read('app/globals.css')),
  'globals.css: an unlayered #main-content:focus-visible rule must suppress the focus ring',
);

check(
  !/<main[^>]*tabIndex/.test(read('app/layout.tsx')),
  'layout.tsx: <main> must not have a static tabIndex (it hijacks the sequential focus starting point on click)',
);

const toc = read('components/docs/Toc.tsx');
const rail = toc.match(/<nav[^>]*className="([^"]*sticky[^"]*)"/);
check(!!rail, 'Toc.tsx: rail nav with sticky className not found');
if (rail) {
  check(/\bmax-h-/.test(rail[1]), 'Toc.tsx: rail nav needs max-h-* so long TOCs stay within the viewport');
  check(/\boverflow-y-auto\b/.test(rail[1]), 'Toc.tsx: rail nav needs overflow-y-auto');
  check(/\bpx-/.test(rail[1]), 'Toc.tsx: rail nav needs horizontal padding so focus rings are not clipped');
}

const layout = read('app/layout.tsx');
const navbar = read('components/layout/Navbar.tsx');
const navZ = Number((navbar.match(/fixed top-0[^"]*\bz-(\d+)\b/) || [])[1]);
const skipZ = Number((layout.match(/#main-content[\s\S]{0,300}?focus:z-\[(\d+)\]/) || [])[1]);
check(Number.isFinite(navZ), 'Navbar.tsx: could not read fixed header z-index');
check(
  Number.isFinite(skipZ) && skipZ > navZ,
  `layout.tsx: skip link focus z-index (${skipZ}) must exceed Navbar z-${navZ}`,
);

import { readdirSync, statSync } from 'node:fs';
const allowScrollMt = new Map([
  ['app/docs/page.tsx', /scroll-mt-4\b/],
  ['components/docs/mdx-components.tsx', /scroll-mt-20\b/],
]);
const walk = (d) =>
  readdirSync(d).flatMap((f) => {
    const full = resolve(d, f);
    return statSync(full).isDirectory() ? walk(full) : /\.tsx?$/.test(f) ? [full] : [];
  });
for (const f of walk(root)) {
  const rel = f.slice(root.length + 1);
  const src = readFileSync(f, 'utf8');
  const hits = src.match(/scroll-mt-[\w.\[\]-]+/g) || [];
  const ok = allowScrollMt.get(rel);
  for (const h of hits) {
    if (!(ok && ok.test(h))) failures.push(`${rel}: unexpected ${h} (stacks with html scroll-padding-top)`);
  }
}

// Guard: utility classes must be backed by @theme tokens (legacy names emit no CSS, #798).
const bad = /(?<![\w-])(?:[\w-]+:)*(?:text-text-[\w-]+|bg-surface|border-surface)(?![\w-])/;
const hoverWhite = /(?<![\w-])(?:group-)?hover:text-white(?![\w-])/;
for (const f of walk(root)) {
  const rel = f.slice(root.length + 1);
  const src = readFileSync(f, 'utf8');
  const m = src.match(bad);
  if (m) failures.push(`${rel}: undefined utility "${m[0]}" (no @theme token; emits no CSS)`);
  const w = src.match(hoverWhite);
  if (w) failures.push(`${rel}: "${w[0]}" is invisible in light mode; use hover:text-fg`);
}

if (failures.length) {
  console.error('Layout guard failures:\n - ' + failures.join('\n - '));
  process.exit(1);
}
console.log('Layout guards OK');
