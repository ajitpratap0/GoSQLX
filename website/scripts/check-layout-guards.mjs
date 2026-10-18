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

if (failures.length) {
  console.error('Layout guard failures:\n - ' + failures.join('\n - '));
  process.exit(1);
}
console.log('Layout guards OK');
