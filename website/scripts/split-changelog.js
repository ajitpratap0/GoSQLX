/**
 * Splits CHANGELOG.md into one Markdown file per released version under
 * src/content/blog/ (rendered at /changelog/<slug>/).
 *
 * Every `## [X.Y.Z]` heading starts a release. Heading formats vary across the
 * file's history, and all of these are accepted:
 *
 *   ## [1.10.4] - 2026-03-14 — AST-based LSP Formatting   (em dash subtitle)
 *   ## [1.9.0] - 2026-02-28 - SQLite PRAGMA, ...           (hyphen subtitle)
 *   ## [1.0.2] - 2025-08-23                               (no subtitle)
 *   ## [0.8.0] - 2023-12-01 [Pre-release]                 (bracketed tag)
 *
 * A release ends at the next `## ` heading of any kind, so trailing non-release
 * sections ("Version History Summary", "Upgrade Guide", "Support") and the
 * `[x.y.z]: https://...` link reference footer never leak into the last page.
 * A heading that starts like a release but cannot be parsed fails the build
 * instead of silently merging into the previous release.
 */
const fs = require('fs');
const path = require('path');

/** Any H2 that starts with a bracketed semantic version is a release heading. */
const RELEASE_HEADING = /^## \[v?(\d+\.\d+\.\d+)\]/;
/** Parses the remainder of a release heading after `## [X.Y.Z]`. */
const HEADING_REST =
  /^\s*(?:[-–—]\s*(\d{4}-\d{2}-\d{2}))?\s*(?:\[([^\]]+)\])?\s*(?:[-–—:]\s*(.*?))?\s*$/;
/** Link reference definitions such as `[1.2.0]: https://github.com/...`. */
const LINK_REF_DEF = /^\[[^\]]+\]:\s+\S+/;

/**
 * @param {string} changelog CHANGELOG.md contents
 * @returns {{version: string, date: string, subtitle: string, body: string}[]}
 */
function splitChangelog(changelog) {
  const lines = changelog.replace(/\r\n?/g, '\n').split('\n');
  const releases = [];
  let current = null;
  let inFence = false;

  const finish = () => {
    if (current) {
      releases.push({ ...current, body: current.body.join('\n').trim() });
    }
    current = null;
  };

  for (const line of lines) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;

    if (!inFence && line.startsWith('## ')) {
      finish();
      const match = line.match(RELEASE_HEADING);
      if (!match) continue; // [Unreleased] or a trailing non-release section
      const rest = line.slice(match[0].length).match(HEADING_REST);
      if (!rest) {
        throw new Error(`split-changelog: cannot parse release heading: ${line}`);
      }
      const subtitle = (rest[3] || rest[2] || '').trim();
      current = { version: match[1], date: rest[1] || '', subtitle, body: [] };
      continue;
    }

    if (!current) continue;
    if (!inFence && LINK_REF_DEF.test(line)) continue;
    current.body.push(line);
  }
  finish();

  // Drop a trailing horizontal rule left over from section separators.
  return releases.map((r) => ({ ...r, body: r.body.replace(/\n+-{3,}\s*$/, '').trim() }));
}

function slugFor(version) {
  return `v${version.replace(/\./g, '-')}`;
}

function toMarkdown(release) {
  const { version, date, subtitle, body } = release;
  const title = subtitle ? `v${version} — ${subtitle}` : `v${version}`;
  const descLine = body
    .split('\n')
    .find((l) => l.trim() && !l.startsWith('#') && !l.startsWith('---') && !l.startsWith('- '));
  const rawDesc = (descLine || subtitle || `GoSQLX v${version} release`)
    .replace(/\*\*/g, '')
    .replace(/`/g, '')
    .trim();
  const description = rawDesc.slice(0, 160).replace(/"/g, "'").replace(/'$/, '');
  const frontmatter = [
    '---',
    `title: "${title.replace(/"/g, "'")}"`,
    `date: "${date}"`,
    `version: "${version}"`,
    `description: "${description}"`,
    '---',
  ].join('\n');
  return `${frontmatter}\n\n${body}\n`;
}

function main() {
  const changelogPath = path.resolve(__dirname, '../../CHANGELOG.md');
  const blogDir = path.resolve(__dirname, '../src/content/blog');

  fs.mkdirSync(blogDir, { recursive: true });
  for (const file of fs.readdirSync(blogDir).filter((f) => f.endsWith('.md'))) {
    fs.unlinkSync(path.join(blogDir, file));
  }

  const releases = splitChangelog(fs.readFileSync(changelogPath, 'utf-8'));
  let count = 0;
  for (const release of releases) {
    if (!release.body) continue;
    fs.writeFileSync(path.join(blogDir, `${slugFor(release.version)}.md`), toMarkdown(release));
    count++;
  }
  console.log(`Generated ${count} changelog pages from CHANGELOG.md`);
}

module.exports = { splitChangelog, slugFor, RELEASE_HEADING };

if (require.main === module) {
  main();
}
