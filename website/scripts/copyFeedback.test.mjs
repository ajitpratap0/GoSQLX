import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCopyFeedback } from '../src/components/playground/useCopyFeedback.ts';

test('copy success and failure reset to idle after the feedback duration', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const states = [];
  const feedback = createCopyFeedback((state) => states.push(state), 2000);
  for (const state of ['copied', 'failed']) {
    feedback.flash(state);
    assert.equal(states.at(-1), state);
    t.mock.timers.tick(1999);
    assert.equal(states.at(-1), state);
    t.mock.timers.tick(1);
    assert.equal(states.at(-1), 'idle');
  }
});

test('a second flash replaces feedback and restarts its reset timer', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const states = [];
  const feedback = createCopyFeedback((state) => states.push(state), 2000);
  feedback.flash('copied');
  t.mock.timers.tick(1500);
  feedback.flash('failed');
  t.mock.timers.tick(500);
  assert.deepEqual(states, ['copied', 'failed']);
  t.mock.timers.tick(1500);
  assert.deepEqual(states, ['copied', 'failed', 'idle']);
  t.mock.timers.runAll();
  assert.equal(states.length, 3);
});

test('dispose on unmount cancels the reset and ignores late clipboard completion', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const states = [];
  const feedback = createCopyFeedback((state) => states.push(state), 2000);
  feedback.flash('copied');
  feedback.dispose();
  feedback.dispose();
  feedback.flash('failed');
  t.mock.timers.runAll();
  assert.deepEqual(states, ['copied']);
});
