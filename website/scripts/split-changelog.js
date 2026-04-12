const fs = require('fs');
const path = require('path');

const changelogPath = path.resolve(__dirname, '../../CHANGELOG.md');
const blogDir = path.resolve(__dirname, '../src/content/blog');

// Ensure blog directory exists
fs.mkdirSync(blogDir, { recursive: true });

// Clear existing generated blog posts
const existing = fs.readdirSync(blogDir).filter(f => f.endsWith('.md'));
for (const file of existing) {
  fs.unlinkSync(path.join(blogDir, file));
}

const changelog = fs.readFileSync(changelogPath, 'utf-8');

// Split on ## [X.Y.Z] headers
// Matches: ## [1.10.4] - 2026-03-14 — AST-based LSP Formatting
const versionRegex = /^## \[(\d+\.\d+\.\d+)\]\s*-?\s*(\d{4}-\d{2}-\d{2})?\s*(?:—\s*(.*))?$/;

const lines = changelog.split('\n');
const releases = [];
let current = null;

for (const line of lines) {
  const match = line.match(versionRegex);
  if (match) {
    if (current) {
      releases.push(current);
    }
    current = {
      version: match[1],
      date: match[2] || '',
      subtitle: (match[3] || '').trim(),
      body: [],
    };
  } else if (line.match(/^## \[Unreleased\]/i)) {
    // End any current section, skip Unreleased
    if (current) {
      releases.push(current);
    }
    current = null;
  } else if (current) {
    current.body.push(line);
  }
}

if (current) {
  releases.push(current);
}

let count = 0;
for (const release of releases) {
  const { version, date, subtitle } = release;
  const body = release.body.join('\n').trim();

  // Skip empty sections
  if (!body) continue;

  const slug = `v${version.replace(/\./g, '-')}`;
  const titleParts = [`v${version}`];
  if (subtitle) titleParts.push(`\u2014 ${subtitle}`);
  const title = titleParts.join(' ');

  // Extract first non-empty, non-heading, non-list line as description
  const descLine = release.body.find(l => l.trim() && !l.startsWith('#') && !l.startsWith('---') && !l.startsWith('- '));
  const rawDesc = (descLine || subtitle || `GoSQLX v${version} release`).replace(/\*\*/g, '').replace(/`/g, '').trim();
  // YAML-safe: escape quotes, strip trailing truncated quotes, limit length
  const description = rawDesc.slice(0, 160).replace(/"/g, "'").replace(/'$/, '');

  const frontmatter = [
    '---',
    `title: "${title}"`,
    `date: "${date}"`,
    `version: "${version}"`,
    `description: "${description}"`,
    '---',
  ].join('\n');

  const content = `${frontmatter}\n\n${body}\n`;
  fs.writeFileSync(path.join(blogDir, `${slug}.md`), content);
  count++;
}

console.log(`Generated ${count} blog posts from CHANGELOG.md`);
