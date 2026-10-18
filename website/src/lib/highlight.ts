import { createHighlighter, createJavaScriptRegexEngine, type Highlighter } from 'shiki';
import { createCssVariablesTheme } from 'shiki/core';

/**
 * Build-time syntax highlighting (server only; ships no JS to the browser).
 *
 * Tokens are coloured with CSS variables (`--shiki-token-*`) instead of a fixed
 * palette. globals.css maps those variables onto the semantic design tokens, so a
 * single highlighted HTML output follows html.light / dark mode with no
 * per-theme markup and no html.light override rules.
 */
const THEME = createCssVariablesTheme({
  name: 'gosqlx-tokens',
  variablePrefix: '--shiki-',
  variableDefaults: {},
  fontStyle: true,
});

export const THEME_NAME = 'gosqlx-tokens';

/** Fence languages used across docs/, CHANGELOG.md and blog articles. Anything else renders as plain text. */
const LANGS = [
  'go',
  'bash',
  'shellscript',
  'sql',
  'yaml',
  'json',
  'jsonc',
  'lua',
  'java',
  'python',
  'emacs-lisp',
  'typescript',
  'javascript',
  'tsx',
  'markdown',
  'docker',
  'viml',
  'ruby',
  'ini',
  'toml',
  'diff',
  'c',
  'makefile',
  'html',
  'xml',
  'proto',
] as const;

let highlighterPromise: Promise<Highlighter> | null = null;

export function getHighlighter(): Promise<Highlighter> {
  if (!highlighterPromise) {
    highlighterPromise = createHighlighter({
      themes: [THEME],
      langs: [...LANGS],
      engine: createJavaScriptRegexEngine({ forgiving: true }),
    });
  }
  return highlighterPromise;
}

/** Map a fence info string to a loaded language, or 'text' when unknown. */
export function resolveLang(highlighter: Highlighter, lang: string | undefined): string {
  if (!lang) return 'text';
  const normalized = lang.toLowerCase();
  if (normalized === 'text' || normalized === 'txt' || normalized === 'plaintext') return 'text';
  return highlighter.getLoadedLanguages().includes(normalized) ? normalized : 'text';
}
