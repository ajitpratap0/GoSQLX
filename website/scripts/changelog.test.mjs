// Unit tests for the changelog pipeline: CHANGELOG.md splitting (scripts/split-changelog.js)
// and the remark plugins used to render each release page (src/lib/remark-changelog.ts).
// Run with `npm test` (node --test; Node >= 22.18 loads the .ts file via type stripping).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { remark } from 'remark';
import { remarkChangelogHeadings, remarkGithubIssueRefs } from '../src/lib/remark-changelog.ts';

const require = createRequire(import.meta.url);
const { splitChangelog, slugFor, describe } = require('./split-changelog.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const changelog = readFileSync(path.resolve(here, '../../CHANGELOG.md'), 'utf-8');

/** Release headings counted independently of the splitter's own regex. */
const headingVersions = changelog
  .split(/\r?\n/)
  .filter((l) => l.startsWith('## [') && !/^## \[Unreleased\]/i.test(l))
  .map((l) => l.slice(4, l.indexOf(']')));

test('CHANGELOG.md: one page per release heading, in file order', () => {
  const releases = splitChangelog(changelog);
  assert.ok(headingVersions.length > 0);
  assert.equal(releases.length, headingVersions.length);
  assert.deepEqual(
    releases.map((r) => r.version),
    headingVersions,
  );
  const slugs = new Set(releases.map((r) => slugFor(r.version)));
  assert.equal(slugs.size, releases.length, 'slugs must be unique');
  for (const r of releases) {
    assert.ok(r.body.length > 0, `v${r.version} has an empty body`);
    assert.match(r.date, /^\d{4}-\d{2}-\d{2}$/, `v${r.version} has no date`);
  }
});

test('CHANGELOG.md: no release body contains another H2 or the link footer', () => {
  for (const r of splitChangelog(changelog)) {
    assert.doesNotMatch(r.body, /^## /m, `v${r.version} contains an H2`);
    assert.doesNotMatch(r.body, /^\[[^\]]+\]:\s+https?:/m, `v${r.version} contains link refs`);
    assert.doesNotMatch(r.body, /Version History Summary/);
    // The 0.9.0 -> 1.0.0 upgrade guide lives inside [1.0.0] as H3s (#787).
  }
});

test('CHANGELOG.md: v1.0.0 page keeps the upgrade guide and v1.9.1 exists', () => {
  const rel = splitChangelog(changelog);
  const v100 = rel.find((r) => r.version === '1.0.0');
  assert.ok(v100, 'v1.0.0 missing');
  assert.match(v100.body, /^### Upgrade Guide \(0\.9\.0 to 1\.0\.0\)/m);
  assert.match(v100.body, /^### Breaking Changes in 1\.0\.0/m);
  assert.ok(rel.some((r) => r.version === '1.9.1'), 'v1.9.1 missing');
});

test('splitChangelog: handles every heading variant and drops trailing sections', () => {
  const md = [
    '# Changelog',
    '## [Unreleased]',
    '- pending',
    '## [1.10.4] - 2026-03-14 — Em Dash',
    '- a',
    '## [1.9.0] - 2026-02-28 - Hyphen Subtitle',
    '- b',
    '```',
    '## [9.9.9] not a heading inside a fence',
    '```',
    '## [1.0.2] - 2025-08-23',
    '- c',
    '## [0.8.0] - 2023-12-01 [Pre-release]',
    '- d',
    '---',
    '## Support',
    '- help',
    '[0.8.0]: https://github.com/ajitpratap0/GoSQLX/releases/tag/v0.8.0',
  ].join('\n');
  const releases = splitChangelog(md);
  assert.deepEqual(
    releases.map((r) => [r.version, r.date, r.subtitle]),
    [
      ['1.10.4', '2026-03-14', 'Em Dash'],
      ['1.9.0', '2026-02-28', 'Hyphen Subtitle'],
      ['1.0.2', '2025-08-23', ''],
      ['0.8.0', '2023-12-01', 'Pre-release'],
    ],
  );
  assert.match(releases[1].body, /## \[9\.9\.9\]/);
  assert.equal(releases[3].body, '- d');
});

test('splitChangelog: an unparsable release heading fails loudly', () => {
  assert.throws(() => splitChangelog('## [1.2.3] ??? garbage ]\n- x'), /cannot parse release heading/);
});

async function render(md) {
  const file = await remark().use(remarkChangelogHeadings).use(remarkGithubIssueRefs).process(md);
  return String(file);
}

test('remarkChangelogHeadings: body starts at h2 and never skips a level', async () => {
  const out = await render('### Added\n\n#### Detail\n\n###### Deep\n\n### Fixed\n');
  assert.equal(out, '## Added\n\n### Detail\n\n#### Deep\n\n## Fixed\n');
});

test('remarkGithubIssueRefs: links bare #N, skips code, links and entities', async () => {
  const out = await render('Fixed (#517, PR #44) and `#12`; see [#9](https://x.test) and a#1.\n');
  assert.equal(
    out,
    'Fixed ([#517](https://github.com/ajitpratap0/GoSQLX/issues/517), PR ' +
      '[#44](https://github.com/ajitpratap0/GoSQLX/issues/44)) and `#12`; see [#9](https://x.test) and a#1.\n',
  );
});

test('splitChangelog: un-bulleted [TAG] lines become list items', () => {
  const md = [
    '## [1.9.0] - 2026-02-28 - Tags',
    '### Fixes',
    '[CLI-1/2]   token_count fixed',
    '[SEC-2]     UNION split: A (CRITICAL, +',
    '            NULL padding)',
    '```',
    '[KEEP-1] inside a fence',
    '```',
    '[1.9.0]: https://example.test/v1.9.0',
  ].join('\n');
  const [release] = splitChangelog(md);
  assert.equal(
    release.body,
    [
      '### Fixes',
      '- [CLI-1/2] token_count fixed',
      '- [SEC-2] UNION split: A (CRITICAL, +',
      '            NULL padding)',
      '```',
      '[KEEP-1] inside a fence',
      '```',
    ].join('\n'),
  );
});

test('changelog article links are underlined, not marked by colour alone (WCAG 1.4.1)', () => {
  const page = readFileSync(path.resolve(here, '../src/app/changelog/[slug]/page.tsx'), 'utf-8');
  assert.match(page, /prose-a:underline\b/);
  assert.doesNotMatch(page, /prose-a:no-underline/);
});

/** Orders "X.Y.Z" strings numerically, newest first. */
const byVersionDesc = (a, b) => {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pb[i] - pa[i];
  return 0;
};

test('CHANGELOG.md: release dates never increase as versions decrease', () => {
  const releases = splitChangelog(changelog).sort((a, b) => byVersionDesc(a.version, b.version));
  for (let i = 1; i < releases.length; i++) {
    const newer = releases[i - 1];
    const older = releases[i];
    assert.ok(
      older.date <= newer.date,
      `v${older.version} (${older.date}) is dated after v${newer.version} (${newer.date})`,
    );
  }
});

test('describe: card summaries are whole sentences, never nested bullets or fragments', () => {
  for (const r of splitChangelog(changelog)) {
    const d = describe(r);
    assert.ok(d.length > 0 && d.length <= 160, `v${r.version}: bad length ${d.length}`);
    assert.doesNotMatch(d, /^[-*+]\s/, `v${r.version}: starts with a bullet: ${d}`);
    assert.doesNotMatch(d, /[,;:]$/, `v${r.version}: ends mid-sentence: ${d}`);
    assert.doesNotMatch(d, /\*\*|`/, `v${r.version}: contains Markdown: ${d}`);
  }
});

test('describe: prefers the full lead paragraph, then the subtitle, then a bullet', () => {
  const lead = describe({
    version: '9.0.0',
    subtitle: 'Sub',
    body: 'First line of the lead,\nsecond line ends here.\n\n### Added\n- x',
  });
  assert.equal(lead, 'First line of the lead, second line ends here.');
  const sub = describe({
    version: '9.0.0',
    subtitle: 'MCP Server',
    body: '### New\n- **MCP** server\n  - 7 tools: a, b\n\n### Note\nLater prose,',
  });
  assert.equal(sub, 'MCP Server');
  const bullet = describe({ version: '9.0.0', subtitle: 'Pre-release', body: '- **Initial** `parser`\n- y' });
  assert.equal(bullet, 'Initial parser');
  const long = describe({ version: '9.0.0', subtitle: '', body: 'word '.repeat(60).trim() });
  assert.ok(long.length <= 160 && long.endsWith('…'));
});

test('changelog article tables scroll horizontally instead of being clipped on narrow screens', () => {
  const page = readFileSync(path.resolve(here, '../src/app/changelog/[slug]/page.tsx'), 'utf-8');
  assert.match(page, /\[&_table\]:overflow-x-auto/);
  assert.match(page, /\[&_table\]:block/);
});

test('splitChangelog strips leading emoji from section headings only', () => {
  const md = '## [1.0.0] - 2026-01-01\n\n### ✨ New Features\n- 🚀 keep me\n\n### 🏷️ Tagged\n\n```\n### 🔧 in fence\n```\n';
  const [r] = splitChangelog(md);
  assert.match(r.body, /^### New Features$/m);
  assert.match(r.body, /^### Tagged$/m);
  assert.match(r.body, /- 🚀 keep me/);
  assert.match(r.body, /### 🔧 in fence/);
});
