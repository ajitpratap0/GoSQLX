import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

const components = new URL('../src/components/playground/', import.meta.url).href;
// Transpile the real component graph in process. Only the CodeMirror boundary
// is replaced: server rendering needs no DOM or editor implementation.
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (context.parentURL?.startsWith(components) && specifier.startsWith('./')) {
      const url = new URL(specifier, context.parentURL);
      for (const extension of ['.tsx', '.ts']) {
        if (existsSync(new URL(url.href + extension))) {
          return nextResolve(url.href + extension, context);
        }
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (!url.startsWith(components) || !/\.tsx?$/.test(url)) {
      return nextLoad(url, context);
    }
    if (url.endsWith('/SqlEditor.tsx')) {
      return {
        format: 'module', shortCircuit: true,
        source: `import { createElement } from 'react';
          export default function SqlEditor({ value, readOnly }) {
            return createElement('pre', { 'data-editor-stub': true, 'data-read-only': readOnly }, value);
          }`,
      };
    }
    const { outputText } = ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      fileName: new URL(url).pathname,
      compilerOptions: {
        jsx: ts.JsxEmit.ReactJSX,
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    });
    return { format: 'module', shortCircuit: true, source: outputText };
  },
});
after(() => hooks.deregister());

const { SqlOutput } = await import('../src/components/playground/FormatTab.tsx');
const { default: TranspileTab } = await import('../src/components/playground/TranspileTab.tsx');
const renderOutput = (data) => renderToStaticMarkup(createElement(SqlOutput, {
  data, label: 'Formatted SQL', errorTitle: 'Format Error', emptyText: 'Waiting for SQL',
}));
const renderTranspile = (data) => renderToStaticMarkup(createElement(TranspileTab, {
  data,
  dialects: [{ value: 'generic', label: 'Generic' }, { value: 'postgresql', label: 'PostgreSQL' }],
  from: 'generic', to: 'postgresql', onFromChange() {}, onToChange() {},
}));

for (const [name, render, title, copyLabel, emptyText] of [
  ['SqlOutput', renderOutput, 'Format Error', 'formatted sql', 'Waiting for SQL'],
  ['TranspileTab', renderTranspile, 'Transpile Error', 'transpiled sql', 'No data available. Enter a SQL query to transpile it.'],
]) {
  test(`${name} renders a polite error with hint and help, without SQL output controls`, () => {
    const markup = render({ error: 'boom Hint: fix it Help: https://x.dev/e', result: '' });
    assert.ok(markup.includes(title));
    assert.match(markup, /role="status"/);
    assert.match(markup, /aria-live="polite"/);
    assert.match(markup, />boom<\/p>/);
    assert.match(markup, /Hint: /);
    assert.match(markup, /fix it/);
    assert.match(markup, /href="https:\/\/x.dev\/e"/);
    assert.ok(!markup.includes(`Copy ${copyLabel}`));
    assert.ok(!markup.includes('read-only'));
    assert.ok(!markup.includes('data-editor-stub'));
    if (name === 'TranspileTab') {
      assert.match(markup, /<select id="transpile-from"/);
      assert.match(markup, /<select id="transpile-to"/);
    }
  });

  test(`${name} renders successful SQL with copy controls`, () => {
    const markup = render({ result: 'SELECT 1' });
    assert.ok(markup.includes(`aria-label="Copy ${copyLabel} to clipboard"`));
    assert.match(markup, /data-read-only="true"/);
    assert.match(markup, />SELECT 1<\/pre>/);
    assert.ok(!markup.includes('role="status"'));
    assert.ok(!markup.includes(title));
  });

  test(`${name} renders its empty state without SQL output controls`, () => {
    const markup = render(null);
    assert.ok(markup.includes(emptyText));
    assert.ok(!markup.includes(`Copy ${copyLabel}`));
    assert.ok(!markup.includes('data-editor-stub'));
  });
}

test('SqlOutput renders an error without a hint or help link', () => {
  const markup = renderOutput({ error: 'x', result: '' });
  assert.match(markup, /Format Error/);
  assert.match(markup, />x<\/p>/);
  assert.ok(!markup.includes('Hint:'));
  assert.ok(!markup.includes('Error code help'));
});
