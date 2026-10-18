#!/usr/bin/env node
/**
 * Regression gate for the markdown pipeline (#748, #749, #753, #762).
 * Run after `npm run build`; it reads the prerendered HTML in .next/server/app.
 *
 * - Every <pre> on docs, blog and changelog pages is Shiki-highlighted
 *   (class="shiki", token spans coloured through var(--shiki-token-*)) and has
 *   a copy button.
 * - The marketing code blocks (/vscode, /benchmarks) use the same component.
 * - Single line breaks render as <br> (metadata lines, release-note entries).
 * - No page applies inline-code padding utilities to all code (prose-code:px-*),
 *   which indented the first line of every block.
 *
 * Usage: node scripts/check-rendered-markdown.mjs
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP = resolve(dirname(fileURLToPath(import.meta.url)), '../.next/server/app');
if (!existsSync(APP)) {
  console.error('No build output found: run `npm run build` first.');
  process.exit(1);
}

function htmlFiles(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...htmlFiles(p));
    else if (name.endsWith('.html')) out.push(p);
  }
  return out;
}

const count = (s, re) => (s.match(re) || []).length;
const failures = [];

const markdownPages = [
  ...htmlFiles(join(APP, 'docs')),
  ...htmlFiles(join(APP, 'blog')),
  ...htmlFiles(join(APP, 'changelog')),
];
const pages = [...markdownPages, join(APP, 'vscode.html'), join(APP, 'benchmarks.html')];

let blocks = 0;
for (const file of pages) {
  const rel = relative(APP, file);
  if (!existsSync(file)) {
    failures.push(`${rel}: missing from build output`);
    continue;
  }
  const html = readFileSync(file, 'utf8');
  const pre = count(html, /<pre[\s>]/g);
  const shiki = count(html, /<pre[^>]*class="shiki"/g);
  const copy = count(html, /aria-label="Copy code"/g);
  blocks += pre;
  if (pre !== shiki) failures.push(`${rel}: ${pre - shiki} of ${pre} <pre> blocks are not highlighted`);
  if (copy !== pre) failures.push(`${rel}: ${pre} <pre> blocks but ${copy} copy buttons`);
  if (/prose-code:p[xy]-/.test(html)) failures.push(`${rel}: prose-code padding utility pads code inside <pre>`);
}

const mustHave = [
  ['docs/getting-started.html', /var\(--shiki-token-keyword\)|var\(--shiki-token-function\)/, 'token-coloured spans'],
  ['vscode.html', /<pre[^>]*class="shiki"[^>]*data-language="json"|<pre[^>]*data-language="json"[^>]*class="shiki"/, 'highlighted JSON settings'],
  ['docs/migration/from-jsqlparser.html', /You Should Stay with JSQLParser If[\s\S]{0,400}?<br\/>/, '<br> between checklist lines'],
  ['changelog/v1-9-2.html', /SQLite PRAGMA parsing[^<]*<br\/>/, '<br> between release-note entries'],
];
for (const [rel, re, what] of mustHave) {
  const file = join(APP, rel);
  if (!existsSync(file)) failures.push(`${rel}: missing from build output`);
  else if (!re.test(readFileSync(file, 'utf8'))) failures.push(`${rel}: expected ${what}`);
}

if (blocks === 0) failures.push('no <pre> blocks found at all: did the pipeline change?');

if (failures.length) {
  console.error(`Rendered markdown check failed (${failures.length}):\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log(`Rendered markdown OK: ${blocks} code blocks on ${pages.length} pages highlighted with copy buttons; line breaks preserved.`);
