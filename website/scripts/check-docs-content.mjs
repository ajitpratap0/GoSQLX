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
 *  - no `gosqlx lint` flag that cmd/gosqlx/cmd does not define, and no mention of
 *    --rules, --list-rules, --show-config, --init-config;
 *  - the error-code count claimed in ERROR_CODES.md matches pkg/errors;
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

/** Long flag names registered in cmd/gosqlx/cmd (lint's own flags plus the global ones). */
function realLintFlags() {
  const flags = new Set(['--help']);
  for (const f of ['lint.go', 'root.go']) {
    const text = readFileSync(join(repoRoot, 'cmd', 'gosqlx', 'cmd', f), 'utf8');
    const re = f === 'lint.go' ? /lintCmd\.Flags\(\)\.\w+\([^"\n]*"([a-z-]+)"/g : /rootCmd\.PersistentFlags\(\)\.\w+\([^"\n]*"([a-z-]+)"/g;
    for (const m of text.matchAll(re)) flags.add(`--${m[1]}`);
  }
  return flags;
}
const REAL_LINT_FLAGS = realLintFlags();

/** Per-line checks. Rules marked `fenced` also run inside fenced code blocks. */
const LINE_RULES = [
  {
    name: 'hand-written version/date line',
    re: /^\s*\**([A-Za-z ]+ )?(Version|Last Updated|Last updated)\**\s*:/i,
    hint: 'remove it; the site shows the release badge and a git-derived date',
  },
  {
    name: 'per-release heading label',
    re: /^#{1,6}\s+(?:v\d+\.\d+(?:\.\d+)?\b|.*(\(\s*[^)]*\bv\d+\.\d+(\.\d+)?\+?[^)]*\)|\bNEW v\d+\.\d+|\bNew in v\d|\bAdded in v\d|\bin v\d+\.\d+(\.\d+)?\s*$))/i,
    hint: 'evergreen docs should not label headings with a release',
  },
  {
    name: 'bold per-release callout',
    re: /^>?\s*\*\*v\d+\.\d+(?:\.\d+)?\*\*\s*:/,
    hint: 'write "Since vX.Y.Z, ..." or just state the current behaviour',
    skip: (file) => file.endsWith('CHANGELOG.md'),
  },
  {
    name: 'inline NEW vX.Y.Z marker',
    re: /\bNEW v\d+\.\d+\.\d+/,
    hint: 'drop the marker or say "since vX.Y.Z"',
  },
  {
    name: 'bare release label in body text',
    re: /\((?:v1\.\d+(?:\.\d+)?(?:\+|\s*-\s*v\d+\.\d+(?:\.\d+)?)?)\)/,
    hint: 'write "since vX.Y.Z" or drop the label',
    skip: (file) => file.endsWith('CHANGELOG.md'),
  },
  {
    name: 'nonexistent gosqlx lint flag',
    test: (line) => {
      const m = line.match(/gosqlx lint\b([^\n|]*)/);
      if (!m) return false;
      return [...m[1].matchAll(/(?:^|\s)(--[a-z][a-z-]*)/g)].some((f) => !REAL_LINT_FLAGS.has(f[1]));
    },
    hint: 'gosqlx lint only has --recursive, --pattern, --auto-fix, --max-length, --fail-on-warn, --security, --dialect and the global --verbose, --output, --format',
    fenced: true,
  },
  {
    name: 'nonexistent lint option mentioned in text',
    re: /(?<![\w-])--(?:rules|list-rules|show-config(?:-path)?|init-config)\b/,
    hint: 'the CLI cannot select rules or read .gosqlx.yml; link to LINTING_RULES.md or use pkg/linter/config',
    fenced: true,
    // `gosqlx action` really has --rules/--severity, and SQLFluff has its own --rules.
    skip: (file, line) => file.endsWith('lint-sql-in-ci.md') || /sqlfluff/i.test(line),
  },
  {
    name: 'stale Go requirement',
    re: /(Go 1\.(1\d|2[0-5])\+?(\s+or (higher|later))?\b(?!\.\d)|golang:1\.(1\d|2[0-5])\b|go-version:\s*'1\.(1\d|2[0-5])')/,
    hint: 'the project requires Go 1.26+',
    fenced: true,
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
    } else if (m && m[1][0] === fence[0] && m[1].length >= fence.length) {
      fence = null;
      return;
    }
    for (const rule of LINE_RULES) {
      if (fence !== null && !rule.fenced) continue;
      if (rule.only && !rule.only(file)) continue;
      if (rule.skip && rule.skip(file, line)) continue;
      if (rule.test ? rule.test(line) : rule.re.test(line)) hits.push({ line: i + 1, rule });
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
  return errors;
}

/** Wrong rule-count claims, checked on every rendered doc. */
function checkRuleCounts(text) {
  const size = linterRulesFromSource().size;
  const errors = [];
  for (const m of text.matchAll(/\b(\d+) (?:built-in )?(?:lint(?:ing)? |linter )?rules\b/gi)) {
    if (/\(L001-L0(?:10|30)\)/.test(text.slice(m.index, m.index + m[0].length + 14)) && Number(m[1]) === 10) {
      errors.push(`"${m[0]}" is paired with the full L001-L030 range`);
    } else if (Number(m[1]) > 12 && Number(m[1]) !== size) errors.push(`doc claims "${m[0]}" but ${size} rules ship`);
  }
  for (const m of text.matchAll(/\b(\d+) Linter Rules \(L001-L030\)/g)) {
    if (Number(m[1]) !== size) errors.push(`doc claims "${m[0]}" but ${size} rules ship`);
  }
  return errors;
}

/** Number of ErrorCode constants declared in pkg/errors/errors.go. */
function errorCodeCount() {
  const text = readFileSync(join(repoRoot, 'pkg', 'errors', 'errors.go'), 'utf8');
  return [...text.matchAll(/^\s*ErrCode\w+\s+ErrorCode\s*=\s*"E\d{4}"/gm)].length;
}

function checkErrorCodes(text) {
  const n = errorCodeCount();
  const errors = [];
  if (n === 0) return ['no error codes found in pkg/errors/errors.go (script out of date?)'];
  for (const m of text.matchAll(/\ball (\d+) error codes\b/g)) {
    if (Number(m[1]) !== n) errors.push(`doc claims "${m[0]}" but pkg/errors declares ${n}`);
  }
  return errors;
}

if (process.argv.includes('--self-test')) {
  const seeded = [
    '**Version**: v1.15.0',
    '## Parser Issues (v1.6.0)',
    'Go 1.21 or higher installed',
    '**GoSQLX Version:** v1.9.0',
    '## Quick Reference: What is New in v1.9.0',
    "## Quick Reference: What's New in v1.9.0",
    '### Feature (v1.4+)',
    '## Summary (v1.6.0)',
    'FROM golang:1.21-alpine AS builder',
    '### Company: Startup (Fictional Example)',
    '| MariaDB | Excellent | superset (v1.14.0) |',
    'gosqlx lint --fix queries/*.sql',
    'gosqlx lint --list-rules',
    'gosqlx lint --show-config query.sql',
    'gosqlx lint --severity hint query.sql',
    'gosqlx lint --init-config',
    'Use the `--rules` flag:',
    'run `--show-config-path` to see it',
    '### v1.6.0 (December 2025)',
    '### v1.4.0',
  ];
  const missed = seeded.filter((l) => scanDoc(join(docsDir, 'X.md'), l).length === 0);
  const fenced = scanDoc(join(docsDir, 'X.md'), '```\n**Version**: v1.15.0\n```').length;
  const fencedGo = ['```dockerfile\nFROM golang:1.21-alpine\n```', "```yaml\ngo-version: '1.21'\n```", '```yaml\nimage: golang:1.21\n```'].filter(
    (t) => scanDoc(join(docsDir, 'X.md'), t).length === 0,
  );
  if (missed.length > 0 || fenced !== 0 || fencedGo.length > 0 || checkLintingRules('# Rules\n').length === 0 || checkRuleCounts('- **10 Linter Rules (L001-L030)**: x').length === 0 || checkErrorCodes('covers all 3 error codes').length === 0 || scanDoc(join(docsDir, 'X.md'), 'gosqlx lint --auto-fix -r --dialect mysql --max-length 80 q.sql').length !== 0) {
    console.error('self-test failed', { missed, fenced, fencedGo });
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
  for (const err of checkRuleCounts(text)) {
    failures++;
    console.error(`${relative(repoRoot, file)}: ${err}`);
  }
  if (file.endsWith('ERROR_CODES.md')) {
    for (const err of checkErrorCodes(text)) {
      failures++;
      console.error(`${relative(repoRoot, file)}: ${err}`);
    }
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
