// Unit tests for the benchmark table helpers in src/lib/bench-format.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shortVersion, shortDialect } from '../src/lib/bench-format.ts';

test('shortVersion shortens the pseudo-version forms', () => {
  assert.equal(shortVersion('v0.0.0-20240101123456-7193401bab12'), 'v0.0.0-…7193401b');
  assert.equal(shortVersion('v1.2.4-0.20240101123456-12038786cd34'), 'v1.2.4-…12038786');
  assert.equal(shortVersion('v1.2.4-pre.0.20240101123456-12038786cd34'), 'v1.2.4-…12038786');
});

test('shortVersion leaves non-pseudo versions alone', () => {
  assert.equal(shortVersion('v1.9.0'), 'v1.9.0');
  assert.equal(shortVersion('commit c95aa7c719d0'), 'commit c95aa7c719d0');
});

test('shortDialect drops long parentheticals only', () => {
  assert.equal(shortDialect('MySQL (unmaintained 2018 Vitess fork)'), 'MySQL');
  assert.equal(shortDialect('PostgreSQL (CGo)'), 'PostgreSQL (CGo)');
  assert.equal(shortDialect('Generic'), 'Generic');
});
