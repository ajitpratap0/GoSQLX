#!/usr/bin/env node
/**
 * Fails when banned numeric/claim literals appear outside the metrics data
 * module. Numbers live in website/src/data/metrics.ts only (issue #657).
 *
 * Scanned: website/src (excluding src/data and src/content, which holds
 * immutable historical release notes), README.md, docs/GETTING_STARTED.md and
 * llms.txt. No test framework needed: `node scripts/check-metrics-drift.mjs`.
 *
 * Pass --self-test to confirm the rules still catch a seeded literal.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(websiteDir, '..');

/** @type {{ name: string, re: RegExp, hint: string }[]} */
const RULES = [
  { name: '1.5M', re: /(?<![\w.-])1\.5M(?!\w)/, hint: 'unmeasured peak throughput claim' },
  { name: '1.2k', re: /1\.2k/i, hint: 'stale GitHub star fallback; use the live count' },
  { name: '574_000', re: /574[_,]?000/, hint: 'wrong complex-query figure' },
  { name: 'blastrain', re: /blastrain/i, hint: 'unsourced competitor numbers; wait for the #673 harness JSON' },
  { name: 'averaged over 5 runs', re: /averaged over 5 runs/i, hint: 'methodology is median of 10 runs' },
  { name: 'unqualified <1us', re: /<\s?1\s?[μµu]s/i, hint: 'name the stage and query, e.g. "~0.3 us to parse a simple SELECT"' },
  { name: '85% SQL-99', re: /(?<![\d–-])85% SQL-99/, hint: 'say "~80-85% (estimated)"' },
];

const SKIP_DIRS = new Set(['node_modules', '.next', 'data', 'content']);
const EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.md', '.mdx', '.txt', '.json']);

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(entry)) yield* walk(full);
    } else if (EXTS.has(full.slice(full.lastIndexOf('.')))) {
      yield full;
    }
  }
}

function scanText(text) {
  const hits = [];
  text.split('\n').forEach((line, i) => {
    for (const rule of RULES) if (rule.re.test(line)) hits.push({ line: i + 1, rule });
  });
  return hits;
}

if (process.argv.includes('--self-test')) {
  if (scanText('const x = "1.5M ops/sec";').length === 0) {
    console.error('self-test failed: seeded banned literal was not detected');
    process.exit(1);
  }
  console.log('self-test ok');
  process.exit(0);
}

const files = [
  ...walk(join(websiteDir, 'src')),
  join(repoRoot, 'README.md'),
  join(repoRoot, 'docs', 'GETTING_STARTED.md'),
  join(repoRoot, 'llms.txt'),
];

let failures = 0;
for (const file of files) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  for (const { line, rule } of scanText(text)) {
    failures++;
    console.error(`${relative(repoRoot, file)}:${line}: banned literal "${rule.name}" (${rule.hint})`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} metrics drift violation(s). Move numbers into website/src/data/metrics.ts.`);
  process.exit(1);
}
console.log('metrics drift check passed');
