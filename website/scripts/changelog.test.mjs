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
const { splitChangelog, slugFor } = require('./split-changelog.js');

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
    assert.doesNotMatch(r.body, /Version History Summary|Upgrade Guide/);
  }
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
