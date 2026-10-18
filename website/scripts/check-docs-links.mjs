#!/usr/bin/env node
/**
 * Docs link guard. Every markdown file under docs/ is read on GitHub AND rendered on
 * the website (website/src/lib/docs.ts rewrites relative .md links to /docs/ routes),
 * so links must be written as relative file links. This script fails when a doc has:
 *   1. a link into a local checkout (`](/Users/...)`, `](/home/...)`, `](file:...)`)
 *   2. a root-absolute `](/docs/...)` link (404s on GitHub; use `OTHER.md` instead)
 *   3. a relative link to a file that does not exist
 *   4. an in-page `#anchor` that matches no heading (github-slugger ids, as rehype-slug)
 *   5. a `file.md#anchor` link whose target file has no such heading
 * Fenced code is ignored using CommonMark rules (a closer has no info string), the same
 * rules as stripCodeFences() in src/lib/docs.ts.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import GithubSlugger from 'github-slugger';

const DOCS = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs');

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : e.name.endsWith('.md') ? [p] : [];
  });
}

export function stripFences(content, problems) {
  const out = [];
  let fence = null;
  let openedAt = 0;
  content.split('\n').forEach((line, i) => {
    const m = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence === null) {
      if (m) {
        fence = m[1];
        openedAt = i + 1;
        out.push('');
      } else out.push(line);
    } else {
      if (m && m[1][0] === fence[0] && m[1].length >= fence.length && m[2].trim() === '') fence = null;
      else if (m && m[1] === fence && m[2].trim() !== '') {
        problems?.push(`line ${i + 1}: "${line.trim()}" nested in the fence opened at line ${openedAt}; wrap the outer block in a longer fence`);
      }
      out.push('');
    }
  });
  if (fence !== null) problems?.push(`code fence opened at line ${openedAt} is never closed`);
  return out.join('\n');
}

function rendered(raw) {
  return raw
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\\([_*`])/g, '$1')
    .replace(/[`*]/g, '')
    .replace(/(^|\s)_+([^_\s][^_]*?)_+(?=\s|$)/g, '$1$2')
    .trim();
}

export function headingIds(body) {
  const slugger = new GithubSlugger();
  const ids = new Set();
  for (const m of body.matchAll(/^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$/gm)) ids.add(slugger.slug(rendered(m[1])));
  for (const m of body.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) ids.add(m[1]);
  return ids;
}

export function checkDocs(files) {
  const errors = [];
  const bodies = new Map(
    files.map((f) => {
      const problems = [];
      const body = stripFences(fs.readFileSync(f, 'utf8'), problems);
      for (const p of problems) errors.push(`docs/${path.relative(DOCS, f)}:${p}`);
      return [f, body];
    })
  );
  const idCache = new Map();
  const idsOf = (f) => {
    if (!idCache.has(f)) idCache.set(f, headingIds(bodies.get(f) ?? stripFences(fs.readFileSync(f, 'utf8'))));
    return idCache.get(f);
  };
  for (const [file, body] of bodies) {
    const rel = path.relative(DOCS, file);
    body.split('\n').forEach((line, i) => {
      // Inline code spans are literal text, not links
      const text = line.replace(/`[^`]*`/g, (s) => ' '.repeat(s.length));
      for (const m of text.matchAll(/\]\(<?([^)\s>]+)>?(?:\s+"[^"]*")?\)/g)) {
        const href = m[1];
        const at = `docs/${rel}:${i + 1}`;
        if (/^(\/Users\/|\/home\/|file:)/i.test(href)) {
          errors.push(`${at}: link into a local checkout: ${href}`);
        } else if (href.startsWith('/docs/')) {
          errors.push(`${at}: root-absolute ${href} 404s on GitHub; use a relative .md link`);
        } else if (/^([a-z][a-z0-9+.-]*:|\/)/i.test(href)) {
          continue;
        } else {
          const hashAt = href.indexOf('#');
          const target = hashAt === -1 ? href : href.slice(0, hashAt);
          const hash = hashAt === -1 ? '' : decodeURIComponent(href.slice(hashAt + 1));
          let dest = file;
          if (target) {
            dest = path.resolve(path.dirname(file), target);
            if (!fs.existsSync(dest)) {
              errors.push(`${at}: broken relative link ${href}`);
              continue;
            }
            if (!dest.endsWith('.md') || !dest.startsWith(DOCS + path.sep)) continue;
          }
          if (hash && !idsOf(dest).has(hash.toLowerCase()) && !idsOf(dest).has(hash)) {
            errors.push(`${at}: anchor #${hash} not found in docs/${path.relative(DOCS, dest)}`);
          }
        }
      }
    });
  }
  return errors;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--self-test')) {
    const tmp = fs.mkdtempSync(path.join(DOCS, '.docs-links-selftest-'));
    try {
      const f = path.join(tmp, 'a.md');
      fs.writeFileSync(
        f,
        '# A\n\n[x](/Users/me/a.go) [y](/docs/b/) [z](#nope) [ok](#a)\n\n```md\n# Inner\n```go\n```\n\n[w](#inner)\n'
      );
      const errs = checkDocs([f]);
      const need = ['local checkout', 'root-absolute', '#nope', '#inner', 'nested in the fence'];
      const missing = need.filter((n) => !errs.some((e) => e.includes(n)));
      if (missing.length || errs.length !== need.length) {
        console.error('self-test failed', { missing, errs });
        process.exit(1);
      }
      console.log('docs link guard self-test passed');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    process.exit(0);
  }
  const files = walk(DOCS).filter((f) => !f.includes(`${path.sep}superpowers${path.sep}`));
  const errors = checkDocs(files);
  if (errors.length) {
    console.error(`docs link check failed (${errors.length}):\n` + errors.join('\n'));
    process.exit(1);
  }
  console.log(`docs link check passed (${files.length} files)`);
}
