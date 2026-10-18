// Unit tests for the playground's in-editor parse error marker
// (src/components/playground/editorDiagnostics.ts, #759).
// Run with `npm test` (node --test; Node >= 22.18 loads the .ts file via type stripping).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EditorState, Text } from '@codemirror/state';
import { diagnosticCount, forEachDiagnostic } from '@codemirror/lint';
import {
  describeErrorSpan,
  errorMarkerTransaction,
  announcedErrorMessage,
  markedErrorMessage,
  parseErrorMarker,
  spanToDiagnostic,
} from '../src/components/playground/editorDiagnostics.ts';

const SQL = 'SELECT 1\nFROM t WHERE ) x';
const SPAN = { code: 'E2002', message: 'unexpected )', line: 2, column: 14, end_line: 2, end_column: 15 };

function stateWith(doc, withMarker = true) {
  return EditorState.create({ doc, extensions: withMarker ? [parseErrorMarker()] : [] });
}

function diagnostics(state) {
  const out = [];
  forEachDiagnostic(state, (d, from, to) => out.push({ from, to, severity: d.severity, message: d.message }));
  return out;
}

test('spanToDiagnostic maps line/column to document offsets', () => {
  const doc = Text.of(SQL.split('\n'));
  const d = spanToDiagnostic(doc, SPAN);
  assert.equal(SQL.slice(d.from, d.to), ')');
  assert.equal(d.severity, 'error');
  assert.equal(d.message, describeErrorSpan(SPAN));
  assert.match(d.message, /^Parse error E2002 at line 2, column 14: unexpected \)$/);
});

test('spanToDiagnostic clamps out-of-range positions to the document', () => {
  const doc = Text.of(['SELECT 1']);
  const past = spanToDiagnostic(doc, { message: 'x', line: 9, column: 99, end_line: 12, end_column: 3 });
  assert.deepEqual([past.from, past.to], [8, 8]);
  const before = spanToDiagnostic(doc, { message: 'x', line: 0, column: -4, end_line: 1, end_column: 0 });
  assert.deepEqual([before.from, before.to], [0, 0]);
  // An end before the start collapses to an empty range at the start.
  const reversed = spanToDiagnostic(doc, { message: 'x', line: 1, column: 5, end_line: 1, end_column: 2 });
  assert.deepEqual([reversed.from, reversed.to], [4, 4]);
});

test('errorMarkerTransaction shows the marker and its message', () => {
  const state = stateWith(SQL);
  const spec = errorMarkerTransaction(state, { source: SQL, span: SPAN });
  assert.ok(spec);
  const next = state.update(spec).state;
  assert.equal(diagnosticCount(next), 1);
  const [d] = diagnostics(next);
  assert.equal(SQL.slice(d.from, d.to), ')');
  assert.equal(markedErrorMessage(next), describeErrorSpan(SPAN));
});

test('errorMarkerTransaction ignores a marker computed for other SQL', () => {
  const state = stateWith(SQL);
  assert.equal(errorMarkerTransaction(state, { source: SQL + ' ', span: SPAN }), null);
});

test('errorMarkerTransaction with null clears a marker, and is a no-op when none is shown', () => {
  const empty = stateWith(SQL);
  assert.equal(errorMarkerTransaction(empty, null), null);

  const marked = empty.update(errorMarkerTransaction(empty, { source: SQL, span: SPAN })).state;
  const spec = errorMarkerTransaction(marked, null);
  assert.ok(spec);
  const cleared = marked.update(spec).state;
  assert.equal(diagnosticCount(cleared), 0);
  assert.equal(markedErrorMessage(cleared), null);
});

test('an edit clears the marker and its message', () => {
  const state = stateWith(SQL);
  const marked = state.update(errorMarkerTransaction(state, { source: SQL, span: SPAN })).state;
  const edited = marked.update({ changes: { from: 0, insert: ' ' } }).state;
  assert.equal(diagnosticCount(edited), 0);
  assert.equal(markedErrorMessage(edited), null);
});

test('the announced message survives edits and is reset by a successful parse', () => {
  const state = stateWith(SQL);
  const marked = state.update(errorMarkerTransaction(state, { source: SQL, span: SPAN })).state;
  assert.equal(announcedErrorMessage(marked), describeErrorSpan(SPAN));

  // Typing drops the marker but keeps the announcement, so the same error
  // reported again for the new text is not announced twice.
  const edited = marked.update({ changes: { from: 0, insert: ' ' } }).state;
  assert.equal(markedErrorMessage(edited), null);
  assert.equal(announcedErrorMessage(edited), describeErrorSpan(SPAN));

  // A successful parse (null marker) still clears the announcement.
  const spec = errorMarkerTransaction(edited, null);
  assert.ok(spec);
  assert.equal(announcedErrorMessage(edited.update(spec).state), null);
  assert.equal(errorMarkerTransaction(edited.update(spec).state, null), null);
});

test('an editor without parseErrorMarker() is left alone', () => {
  const state = stateWith(SQL, false);
  assert.equal(errorMarkerTransaction(state, { source: SQL, span: SPAN }), null);
  assert.equal(errorMarkerTransaction(state, null), null);
  assert.equal(markedErrorMessage(state), null);
});
