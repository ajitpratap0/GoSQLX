#!/usr/bin/env node
/**
 * Guards the docs that the website renders (the files listed in DOCS_SIDEBAR)
 * against drift that the visual audit found (issues #743, #751, #771):
 *
 *  - every lint rule defined in pkg/linter/rules must be documented in
 *    docs/LINTING_RULES.md (a `### Lnnn:` section and a summary-table row),
 *    and the doc must not claim a different rule count;
 *  - no hand-written "Version:" / "Last Updated:" lines (the site derives the
 *    date from git and the release badge from the current release);
 *  - no per-release labels such as "(v1.6.0)" or "NEW v1.6.0" in headings;
 *  - no stale Go requirement (the project needs Go 1.26+);
 *  - no hand-written table of contents (the page already has "On this page"),
 *    and no "Fictional Example" wording in migration guides.
 *
 * Run with `node scripts/check-docs-content.mjs`. Pass --self-test to confirm
 * the checks still catch seeded violations.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(websiteDir, '..');
const docsDir = join(repoRoot, 'docs');

/** Per-line checks applied outside fenced code blocks. */
const LINE_RULES = [
  {
    name: 'hand-written version/date line',
    re: /^\s*\**(Version|Last Updated|Last updated)\**\s*:/,
    hint: 'remove it; the site shows the release badge and a git-derived date',
  },
  {
    name: 'per-release heading label',
    re: /^#{1,6}\s.*(\(\s*(NEW\s+)?v\d+\.\d+\.\d+[^)]*\)|\bNEW v\d+\.\d+\.\d+)/,
    hint: 'evergreen docs should not label headings with a release',
  },
  {
    name: 'inline NEW vX.Y.Z marker',
    re: /\bNEW v\d+\.\d+\.\d+/,
    hint: 'drop the marker or say "since vX.Y.Z"',
  },
  {
    name: 'stale Go requirement',
    re: /(Go 1\.(1\d|2[0-5])\+?(\s+or (higher|later))?\b(?!\.\d)|golang:1\.(1\d|2[0-5])\b|go-version:\s*'1\.(1\d|2[0-5])')/,
    hint: 'the project requires Go 1.26+',
    // Benchmark-environment and historical migration notes may name older Go versions.
    skip: (file, line) =>
      file.endsWith('COMPARISON.md') ||
      file.endsWith('MIGRATION.md') ||
      /\(Go 1\.19\+\)/.test(line),
  },
  {
    name: 'hand-written table of contents',
    re: /^##\s+Table of Contents\s*$/,
    hint: 'remove it; the page renders "On this page"',
    only: (file) => file.includes(`${join('docs', 'migration')}`),
  },
  {
    name: 'fictional example wording',
    re: /Fictional Example|Real Migration Case Study/,
    hint: 'use "Example Migration Case Study" and say the scenario is illustrative',
  },
];

function sidebarFiles() {
  const src = readFileSync(join(websiteDir, 'src', 'lib', 'constants.ts'), 'utf8');
  const files = new Set();
  for (const m of src.matchAll(/file:\s*'([^']+\.md)'/g)) files.add(m[1]);
  return [...files].map((f) => join(docsDir, f));
}

/** @param {string} file @param {string} text */
function scanDoc(file, text) {
  const hits = [];
  let fence = null;
  text.split('\n').forEach((line, i) => {
    const m = line.match(/^ {0,3}(`{3,}|~{3,})/);
    if (fence === null) {
      if (m) {
        fence = m[1];
        return;
      }
    } else {
      if (m && m[1][0] === fence[0] && m[1].length >= fence.length) fence = null;
      return;
    }
    for (const rule of LINE_RULES) {
      if (rule.only && !rule.only(file)) continue;
      if (rule.skip && rule.skip(file, line)) continue;
      if (rule.re.test(line)) hits.push({ line: i + 1, rule });
    }
  });
  return hits;
}

/** Rule IDs and names declared with NewBaseRule in pkg/linter/rules. */
function linterRulesFromSource() {
  const ids = new Map();
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith('.go') && !entry.endsWith('_test.go')) {
        const text = readFileSync(full, 'utf8');
        for (const m of text.matchAll(/NewBaseRule\(\s*"(L\d{3})",\s*"([^"]+)"/g)) ids.set(m[1], m[2]);
      }
    }
  };
  walk(join(repoRoot, 'pkg', 'linter', 'rules'));
  return ids;
}

function checkLintingRules(text) {
  const errors = [];
  const rules = linterRulesFromSource();
  if (rules.size === 0) return ['no lint rules found under pkg/linter/rules (script out of date?)'];
  for (const [id, name] of [...rules].sort()) {
    if (!new RegExp(`^###\\s+${id}:`, 'm').test(text)) errors.push(`${id} (${name}) has no "### ${id}:" section`);
    if (!new RegExp(`^\\|\\s*\\[${id}\\]`, 'm').test(text)) errors.push(`${id} (${name}) is missing from the summary table`);
  }
  const last = [...rules.keys()].sort().pop();
  if (!text.includes(`${rules.size} built-in`)) errors.push(`doc does not state the rule count (${rules.size} built-in)`);
  if (!text.includes(`L001-${last}`)) errors.push(`doc does not state the range L001-${last}`);
  for (const m of text.matchAll(/\b(\d+) (?:built-in )?(?:lint(?:ing)? )?rules\b/g)) {
    if (Number(m[1]) > 12 && Number(m[1]) !== rules.size) errors.push(`doc claims "${m[0]}" but ${rules.size} rules ship`);
  }
  return errors;
}

if (process.argv.includes('--self-test')) {
  const seeded = [
    '**Version**: v1.15.0',
    '## Parser Issues (v1.6.0)',
    'Go 1.21 or higher installed',
    'FROM golang:1.21-alpine AS builder',
    '### Company: Startup (Fictional Example)',
  ];
  const missed = seeded.filter((l) => scanDoc(join(docsDir, 'X.md'), l).length === 0);
  const fenced = scanDoc(join(docsDir, 'X.md'), '```\n**Version**: v1.15.0\n```').length;
  if (missed.length > 0 || fenced !== 0 || checkLintingRules('# Rules\n').length === 0) {
    console.error('self-test failed', { missed, fenced });
    process.exit(1);
  }
  console.log('self-test ok');
  process.exit(0);
}

let failures = 0;
for (const file of sidebarFiles()) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    failures++;
    console.error(`${relative(repoRoot, file)}: listed in DOCS_SIDEBAR but missing`);
    continue;
  }
  for (const { line, rule } of scanDoc(file, text)) {
    failures++;
    console.error(`${relative(repoRoot, file)}:${line}: ${rule.name} (${rule.hint})`);
  }
  if (file.endsWith('LINTING_RULES.md')) {
    for (const err of checkLintingRules(text)) {
      failures++;
      console.error(`${relative(repoRoot, file)}: ${err}`);
    }
  }
}

if (failures > 0) {
  console.error(`\n${failures} docs content violation(s).`);
  process.exit(1);
}
console.log('docs content check passed');
