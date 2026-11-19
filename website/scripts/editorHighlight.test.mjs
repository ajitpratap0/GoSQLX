// Unit tests for the playground's GoSQLX syntax highlighting
// (src/components/playground/editorHighlight.ts).
// Run with `npm test` (node --test; Node >= 22.18 loads the .ts file via type stripping).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EditorState } from '@codemirror/state';
import {
  computeHighlight,
  gosqlxHighlighting,
  gosqlxHighlightMarks,
  highlightActivation,
  highlightClass,
  isGosqlxHighlightActive,
  MAX_HIGHLIGHT_LENGTH,
  marksToDecorations,
  setHighlight,
  spansToMarks,
} from '../src/components/playground/editorHighlight.ts';

function ranges(set) {
  const out = [];
  set.between(0, Number.MAX_SAFE_INTEGER, (from, to, deco) => {
    out.push({ from, to, className: deco.spec.class });
  });
  return out;
}

test('highlightClass maps known categories and rejects unknown ones', () => {
  assert.equal(highlightClass('keyword'), 'cm-gsx-keyword');
  assert.equal(highlightClass('quoted-identifier'), 'cm-gsx-quoted-identifier');
  assert.equal(highlightClass('plain'), null);
  assert.equal(highlightClass('bogus'), null);
});

test('spansToMarks keeps valid spans in order', () => {
  const sql = 'SELECT id FROM t';
  const marks = spansToMarks(
    [
      { start: 0, end: 6, category: 'keyword' },
      { start: 7, end: 9, category: 'identifier' },
      { start: 10, end: 14, category: 'keyword' },
    ],
    sql.length,
  );
  assert.deepEqual(marks, [
    { from: 0, to: 6, className: 'cm-gsx-keyword' },
    { from: 7, to: 9, className: 'cm-gsx-identifier' },
    { from: 10, to: 14, className: 'cm-gsx-keyword' },
  ]);
  assert.deepEqual(marks.map((m) => sql.slice(m.from, m.to)), ['SELECT', 'id', 'FROM']);
});

test('spansToMarks clamps to the document and drops bad spans', () => {
  const marks = spansToMarks(
    [
      { start: -2, end: 3, category: 'keyword' }, // clamped start
      { start: 2, end: 4, category: 'number' }, // overlaps the previous span
      { start: 4, end: 4, category: 'number' }, // empty
      { start: 5, end: 6, category: 'unknown' }, // unknown category
      { start: Number.NaN, end: 7, category: 'string' }, // not a number
      { start: 8, end: 99, category: 'error' }, // clamped end
      { start: 1, end: 2, category: 'operator' }, // out of order
    ],
    10,
  );
  assert.deepEqual(marks, [
    { from: 0, to: 3, className: 'cm-gsx-keyword' },
    { from: 8, to: 10, className: 'cm-gsx-error' },
  ]);
});

test('spansToMarks uses UTF-16 offsets as given (JavaScript string indices)', () => {
  const sql = "SELECT '😀' AS x";
  // The bridge reports UTF-16 units: the emoji is two units.
  const marks = spansToMarks(
    [
      { start: 7, end: 11, category: 'string' },
      { start: 15, end: 16, category: 'identifier' },
    ],
    sql.length,
  );
  assert.deepEqual(marks.map((m) => sql.slice(m.from, m.to)), ["'😀'", 'x']);
});

test('marksToDecorations builds a set with one mark per range', () => {
  const set = marksToDecorations([
    { from: 0, to: 6, className: 'cm-gsx-keyword' },
    { from: 7, to: 20, className: 'cm-gsx-comment' }, // multi-line spans are fine
  ]);
  assert.deepEqual(ranges(set), [
    { from: 0, to: 6, className: 'cm-gsx-keyword' },
    { from: 7, to: 20, className: 'cm-gsx-comment' },
  ]);
});

test('computeHighlight returns null when highlighting is unavailable', () => {
  assert.equal(computeHighlight(null, 'SELECT 1'), null);
  assert.equal(computeHighlight(() => null, 'SELECT 1'), null);
  assert.equal(
    computeHighlight(() => {
      throw new Error('gosqlxHighlight is not available');
    }, 'SELECT 1'),
    null,
  );
  assert.equal(computeHighlight(() => ({ spans: [] }), 'SELECT 1'), null); // malformed
});

test('computeHighlight skips documents longer than MAX_HIGHLIGHT_LENGTH', () => {
  let calls = 0;
  const source = () => {
    calls++;
    return [{ start: 0, end: 6, category: 'keyword' }];
  };
  const atLimit = 'SELECT' + ' '.repeat(MAX_HIGHLIGHT_LENGTH - 6);
  assert.notEqual(computeHighlight(source, atLimit), null);
  assert.equal(calls, 1);
  assert.equal(computeHighlight(source, atLimit + ' '), null);
  assert.equal(calls, 1); // the source is not called for an oversized document
});

test('computeHighlight resolves asynchronous sources', async () => {
  const pending = computeHighlight(async () => [{ start: 0, end: 6, category: 'keyword' }], 'SELECT 1');
  assert.ok(pending instanceof Promise);
  assert.deepEqual(ranges(await pending), [{ from: 0, to: 6, className: 'cm-gsx-keyword' }]);

  assert.equal(await computeHighlight(async () => null, 'SELECT 1'), null);
  assert.equal(await computeHighlight(async () => ({ spans: [] }), 'SELECT 1'), null); // malformed
  assert.equal(
    await computeHighlight(async () => {
      throw new Error('worker failed');
    }, 'SELECT 1'),
    null,
  );
});

test('computeHighlight passes the SQL to the source and builds marks', () => {
  let seen = null;
  const set = computeHighlight((sql) => {
    seen = sql;
    return [
      { start: 0, end: 6, category: 'keyword' },
      { start: 7, end: 8, category: 'number' },
    ];
  }, 'SELECT 1');
  assert.equal(seen, 'SELECT 1');
  assert.deepEqual(ranges(set), [
    { from: 0, to: 6, className: 'cm-gsx-keyword' },
    { from: 7, to: 8, className: 'cm-gsx-number' },
  ]);
});

test('the state field tracks activation and maps marks through edits', () => {
  let state = EditorState.create({ doc: 'SELECT 1', extensions: [gosqlxHighlighting()] });
  assert.equal(isGosqlxHighlightActive(state), false);
  assert.equal(gosqlxHighlightMarks(state), null);

  const marks = marksToDecorations([{ from: 0, to: 6, className: 'cm-gsx-keyword' }]);
  let tr = state.update({ effects: setHighlight.of(marks) });
  assert.equal(highlightActivation(tr), true);
  state = tr.state;
  assert.equal(isGosqlxHighlightActive(state), true);

  // Replacing marks while active is not an activation change.
  tr = state.update({ effects: setHighlight.of(marks) });
  assert.equal(highlightActivation(tr), null);

  // An edit before the keyword shifts the mark until the next refresh.
  tr = state.update({ changes: { from: 0, insert: '  ' } });
  assert.equal(highlightActivation(tr), null);
  state = tr.state;
  assert.deepEqual(ranges(gosqlxHighlightMarks(state)), [{ from: 2, to: 8, className: 'cm-gsx-keyword' }]);

  tr = state.update({ effects: setHighlight.of(null) });
  assert.equal(highlightActivation(tr), false);
  assert.equal(isGosqlxHighlightActive(tr.state), false);
});
