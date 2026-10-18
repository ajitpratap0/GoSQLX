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
 * Un-bulleted change lines tagged like `[CLI-3]     analyze ...` (used in the
 * 1.9.0 section). Markdown would join them into one paragraph, so they are
 * emitted as list items; indented continuation lines stay part of the item.
 */
const SECTION_HEADING_EMOJI = /^(#{3,6})\s+(?:\p{Extended_Pictographic}️?‍?)+\s*/u;
const TAGGED_LINE =/^\[[A-Z][A-Z0-9/-]*\]\s/;

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
    if (!inFence && SECTION_HEADING_EMOJI.test(line)) {
      // Section headings drop a leading emoji so anchors and the TOC stay clean.
      current.body.push(line.replace(SECTION_HEADING_EMOJI, '$1 '));
      continue;
    }
    current.body.push(!inFence && TAGGED_LINE.test(line) ? `- ${line.replace(/\s+/, ' ')}` : line);
  }
  finish();

  // Drop a trailing horizontal rule left over from section separators.
  return releases.map((r) => ({ ...r, body: r.body.replace(/\n+-{3,}\s*$/, '').trim() }));
}

function slugFor(version) {
  return `v${version.replace(/\./g, '-')}`;
}

const DESCRIPTION_MAX = 160;

/** Strips inline Markdown so a summary reads as plain text on a card. */
function plainText(md) {
  return md
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\*\*|__|`/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Shortens to at most `max` chars, preferring a sentence end, then a word boundary. */
function truncate(text, max) {
  if (text.length <= max) return text;
  const head = text.slice(0, max);
  const sentenceEnd = Math.max(head.lastIndexOf('. '), head.lastIndexOf('! '), head.lastIndexOf('? '));
  if (sentenceEnd >= max / 2) return head.slice(0, sentenceEnd + 1);
  const space = head.lastIndexOf(' ', max - 1);
  return `${head.slice(0, space > 0 ? space : max - 1).replace(/[\s,;:(—–-]+$/, '')}…`;
}

/**
 * Card summary for a release. In order of preference: the lead paragraph that
 * precedes the first heading (all of its lines, so it is never cut mid-sentence),
 * the heading subtitle, the first top-level bullet, then a generic fallback.
 * Nested bullets, tables, quotes and prose under later headings are never used,
 * because out of context they read as fragments.
 */
function describe(release) {
  const { version, subtitle, body } = release;
  const lead = [];
  for (const line of body.split('\n')) {
    const t = line.trim();
    if (/^(#|```|~~~)/.test(t)) break;
    if (!t) {
      if (lead.length) break;
      continue;
    }
    if (/^([-*+]\s|\d+\.\s|\||>|-{3,}$)/.test(t)) {
      if (lead.length) break;
      continue;
    }
    lead.push(t);
  }
  const firstBullet = body.split('\n').find((l) => /^[-*+]\s+\S/.test(l));
  const candidates = [
    lead.join(' '),
    // A bare status tag such as "Pre-release" says nothing about the release.
    /^(pre-?release|released\b)/i.test(subtitle) ? '' : subtitle,
    firstBullet ? firstBullet.replace(/^[-*+]\s+/, '') : '',
    `GoSQLX v${version} release`,
  ];
  const text = plainText(candidates.find((c) => plainText(c)) || '');
  return truncate(text, DESCRIPTION_MAX).replace(/"/g, "'");
}

function toMarkdown(release) {
  const { version, date, subtitle, body } = release;
  const title = subtitle ? `v${version} — ${subtitle}` : `v${version}`;
  const description = describe(release);
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

module.exports = { splitChangelog, slugFor, describe, RELEASE_HEADING };

if (require.main === module) {
  main();
}
