#!/usr/bin/env node
/**
 * WCAG AA contrast gate for the design tokens in src/app/globals.css (#665).
 *
 * Parses the :root (dark) and html.light (light) token blocks and checks every
 * text/UI token pair against the three surfaces. Text pairs need 4.5:1, UI
 * pairs 3:1. Also fails if an html.light override rule other than the token
 * block comes back (components must use token utilities instead).
 *
 * Usage: node scripts/check-contrast.mjs
 */
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const css = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../src/app/globals.css'),
  'utf8',
);

function block(selector) {
  const start = css.indexOf(`\n${selector} {`);
  if (start < 0) throw new Error(`token block not found: ${selector}`);
  const end = css.indexOf('\n}', start);
  return css.slice(start, end);
}

function tokens(selector) {
  const out = {};
  for (const m of block(selector).matchAll(/--([\w-]+):\s*(#[0-9A-Fa-f]{6})\b/g)) {
    out[m[1]] = m[2];
  }
  return out;
}

function lum(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a, b) {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const SURFACES = ['bg', 'bg-raised', 'bg-overlay'];
const TEXT = ['fg', 'fg-muted', 'fg-subtle', 'accent', 'accent-warm', 'danger', 'ok', 'warn', 'info', 'violet', 'cyan'];
const UI = ['brand'];
const FILLS = [['brand-fg', 'brand'], ['accent-fg', 'accent']];

const themes = { dark: tokens(':root'), light: { ...tokens(':root'), ...tokens('html.light') } };
const failures = [];
let checked = 0;

function check(theme, fg, bg, min, vars) {
  const a = vars[fg];
  const b = vars[bg];
  if (!a || !b) {
    failures.push(`${theme}: missing token ${!a ? fg : bg}`);
    return;
  }
  checked++;
  const r = ratio(a, b);
  if (r < min) failures.push(`${theme}: ${fg} ${a} on ${bg} ${b} = ${r.toFixed(2)}:1 (needs ${min}:1)`);
}

for (const [theme, vars] of Object.entries(themes)) {
  for (const s of SURFACES) {
    for (const t of TEXT) check(theme, t, s, 4.5, vars);
    for (const u of UI) check(theme, u, s, 3, vars);
  }
  for (const [fg, bg] of FILLS) check(theme, fg, bg, 4.5, vars);
}

// Code surfaces stay dark in both themes: their restored tokens are the dark set.
const overrides = css.replace(/\/\*[\s\S]*?\*\//g, '').split('\n').filter((l) => /html\.light/.test(l));
if (overrides.length !== 1 || overrides[0].trim() !== 'html.light {') {
  failures.push(`html.light override rules are not allowed outside the token block:\n  ${overrides.join('\n  ')}`);
}

// Any element using prose-invert must also carry prose-dark, otherwise typography
// falls back to white text and is unreadable in light mode (#736).
const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '../src');
function walk(dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const f = resolve(dir, e.name);
    if (e.isDirectory()) walk(f);
    else if (/\.(tsx|ts|jsx|js)$/.test(e.name)) {
      const src = readFileSync(f, 'utf8');
      if (/\bprose-invert\b/.test(src) && !/\bprose-dark\b/.test(src)) {
        failures.push(`${f.slice(SRC.length)}: prose-invert without prose-dark`);
      }
    }
  }
}
walk(SRC);

// .prose-dark must override every --tw-prose-* variable that prose-invert sets,
// otherwise the invert (light-on-dark) value leaks through in light mode.
const proseDark = (css.match(/\.prose-dark\s*\{([^}]*)\}/) || [])[1] || '';
for (const v of ['body', 'lead', 'headings', 'links', 'bold', 'counters', 'bullets', 'hr', 'quotes', 'quote-borders', 'captions', 'code', 'pre-bg', 'th-borders', 'td-borders']) {
  if (!proseDark.includes(`--tw-prose-${v}:`)) failures.push(`.prose-dark does not override --tw-prose-${v}`);
}

if (failures.length) {
  console.error(`Contrast check failed (${failures.length}):\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log(`Contrast OK: ${checked} pairs meet WCAG AA in dark and light themes.`);
