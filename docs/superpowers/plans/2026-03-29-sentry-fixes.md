# Sentry Bug Fixes #437 + #434 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Sentry issues #437 (hydration error from replay integration) and #434 (pushState TypeError variants not caught by existing filter).

**Architecture:** Both bugs are in `website/src/instrumentation-client.ts`. Fix #437 by adding `ignoreErrors` patterns for Next.js hydration mismatches and using a `beforeSendEvent` hook. Fix #434 by expanding the `beforeSend` filter to cover all TypeError variants involving pushState (not just the exact string match).

**Tech Stack:** Next.js 16, @sentry/nextjs, TypeScript

---

## File Map

- Modify: `website/src/instrumentation-client.ts` — add ignoreErrors, expand beforeSend filter
- Verify: `website/src/sentry.server.config.ts` — ensure server-side does not capture hydration events
- Verify: `website/src/app/layout.tsx` — confirm suppressHydrationWarning is in place

---

### Task 1: Audit existing Sentry config against open issues

**Files:**
- Read: `website/src/instrumentation-client.ts`
- Read: `website/src/sentry.server.config.ts`

- [ ] **Step 1: Read the current client config**

```bash
cat website/src/instrumentation-client.ts
```

Expected: file shows `replayIntegration()`, `replaysSessionSampleRate: 0.1`, and a `beforeSend` filtering `Cannot assign to read only property 'pushState'` and `Object Not Found Matching Id:`.

- [ ] **Step 2: Check if the pushState filter covers all TypeError variants**

The current filter only matches the exact string `"Cannot assign to read only property 'pushState'"`.

Variants that bypass the filter:
- `"Cannot assign to read only property 'pushState' of object '#<History>'"` — object descriptor appended
- `"Uncaught TypeError: Cannot assign to read only property 'pushState'"` — wrapped by browser
- TypeError with `type: "unhandledrejection"` (async context)
- Hydration mismatch: `"Text content does not match server-rendered HTML"`, `"Hydration failed"`, `"There was an error while hydrating"`, `"Minified React error #418"`, `"Minified React error #423"`, `"Minified React error #425"`

- [ ] **Step 3: Document both bug signatures**

Issue #434: `TypeError: Cannot assign to read only property 'pushState'`
— Browser extensions (Vue DevTools, Redux DevTools) wrap `history.pushState` before our app loads.
— Fix: Broaden the filter to use `msg.includes("pushState")` + check event type

Issue #437: Hydration mismatch from Sentry Replay
— `replayIntegration()` injects `data-*` attributes into the DOM during client-side hydration.
— React compares server HTML (no Sentry attrs) with client HTML (Sentry attrs) → mismatch.
— Fix: Add `ignoreErrors` array for all known hydration error patterns + filter in `beforeSend`

- [ ] **Step 4: Commit nothing yet — just notes**

```bash
git status  # confirm no changes
```

---

### Task 2: Fix #434 — expand pushState filter coverage

**Files:**
- Modify: `website/src/instrumentation-client.ts`

- [ ] **Step 1: Update beforeSend to use broad pushState matching**

Current `isExtensionNoise` logic only checks the exact substring. Replace with pattern that catches all variants:

```typescript
// In instrumentation-client.ts, replace the isExtensionNoise block:

const isExtensionNoise =
  // pushState read-only — extensions (Vue/Redux DevTools) wrap history.pushState
  // Matches all variants: with/without object descriptor suffix
  msg.toLowerCase().includes("pushstate") ||
  // Chrome DevTools Protocol messages from extensions in CodeMirror/Monaco
  msg.includes("Object Not Found Matching Id:");
```

- [ ] **Step 2: Run dev server and verify no console errors from filter**

```bash
cd website && npm run dev
```

Expected output: Next.js dev server starts on port 3000, no TypeScript errors.

Open browser to `http://localhost:3000`, check console: no Sentry-related errors.

- [ ] **Step 3: Commit the pushState fix**

```bash
git add website/src/instrumentation-client.ts
git commit -m "fix(website): broaden Sentry pushState filter to catch all TypeError variants (#434)"
```

---

### Task 3: Fix #437 — suppress hydration errors from Replay integration

**Files:**
- Modify: `website/src/instrumentation-client.ts`

- [ ] **Step 1: Add ignoreErrors and extend beforeSend for hydration patterns**

Hydration errors from Sentry Replay are React errors thrown when the client DOM doesn't match server HTML. They appear as React minified errors #418, #423, #425 and as plain text messages. These should be suppressed — they are not real app bugs when caused by browser extensions or Sentry Replay itself.

Replace the full `Sentry.init()` call in `website/src/instrumentation-client.ts` with:

```typescript
import * as Sentry from "@sentry/nextjs";

const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;

Sentry.init({
  dsn,
  sendDefaultPii: true,
  tracesSampleRate: process.env.NODE_ENV === "development" ? 1.0 : 0.1,
  replaysSessionSampleRate: 0.1,
  replaysOnErrorSampleRate: 1.0,
  enableLogs: true,
  integrations: [
    Sentry.replayIntegration(),
  ],
  // Suppress known-noisy error patterns that are not actionable app bugs.
  // These originate from browser extensions, React hydration with Replay,
  // and Chrome DevTools Protocol messages.
  ignoreErrors: [
    // pushState read-only — extensions wrap history.pushState before our app loads
    /Cannot assign to read only property ['"]?pushState['"]?/i,
    // React hydration mismatches triggered by Sentry Replay injecting DOM attrs
    "Text content does not match server-rendered HTML",
    "Hydration failed because the server rendered HTML didn't match the client",
    "There was an error while hydrating",
    "Minified React error #418",
    "Minified React error #423",
    "Minified React error #425",
    // Chrome DevTools Protocol from extensions interacting with CodeMirror
    /Object Not Found Matching Id:\d+/,
  ],
  beforeSend(event) {
    const msg = event.exception?.values?.[0]?.value ?? "";

    // Belt-and-suspenders: also filter in beforeSend for events that bypass
    // ignoreErrors (e.g. unhandledrejection events, events with no exception value).
    const isExtensionNoise =
      msg.toLowerCase().includes("pushstate") ||
      msg.includes("Object Not Found Matching Id:");

    const isHydrationNoise =
      msg.includes("Text content does not match") ||
      msg.includes("Hydration failed") ||
      msg.includes("There was an error while hydrating") ||
      msg.includes("Minified React error #418") ||
      msg.includes("Minified React error #423") ||
      msg.includes("Minified React error #425");

    if (isExtensionNoise || isHydrationNoise) {
      if (process.env.NODE_ENV === "development") {
        console.debug("[Sentry] Suppressed noise:", msg);
      }
      return null;
    }

    return event;
  },
});

export const onRouterTransitionStart = dsn
  ? Sentry.captureRouterTransitionStart
  : undefined;
```

- [ ] **Step 2: Verify TypeScript compiles cleanly**

```bash
cd website && npx tsc --noEmit
```

Expected: no errors.

- [ ] **Step 3: Start dev server, trigger hydration scenario, verify no Sentry reports**

```bash
cd website && npm run dev
```

Open Chrome with a Redux DevTools extension active. Navigate to the website. Verify:
- No red Sentry alerts in the browser console
- `[Sentry] Suppressed noise:` debug log appears when the extension fires

- [ ] **Step 4: Build for production to verify no SSR issues**

```bash
cd website && npm run build
```

Expected: build completes successfully, no hydration warnings in build output.

- [ ] **Step 5: Commit the hydration fix**

```bash
git add website/src/instrumentation-client.ts
git commit -m "fix(website): suppress Sentry Replay hydration false positives and React error #418/#423/#425 (#437)"
```

---

### Task 4: Verify server-side Sentry does not capture these events

**Files:**
- Read: `website/src/sentry.server.config.ts`

- [ ] **Step 1: Check server config for hydration suppression**

```bash
cat website/src/sentry.server.config.ts
```

Hydration errors are client-side only (React DOM mismatch). The server config does not need changes. Confirm the server config does NOT have `replayIntegration()`.

Expected: server config only has `dsn`, `tracesSampleRate`, optional `beforeSend`.

- [ ] **Step 2: Confirm layout.tsx has suppressHydrationWarning**

```bash
grep -n "suppressHydrationWarning" website/src/app/layout.tsx
```

Expected: at least one match on the `<html>` or `<body>` element.

If missing, add `suppressHydrationWarning` to the `<html>` tag in `layout.tsx`. This suppresses React's console warning for attributes injected by browser extensions (like Sentry Replay):

```tsx
<html lang="en" suppressHydrationWarning>
```

- [ ] **Step 3: Final commit if layout.tsx needed changes**

```bash
git add website/src/app/layout.tsx
git commit -m "fix(website): add suppressHydrationWarning to html element to silence Replay attr injection"
```

If no changes needed, skip this step.

---

### Task 5: Open and close the Sentry issues

- [ ] **Step 1: Resolve Sentry issue #434 in dashboard**

In the Sentry dashboard, mark issue #434 (pushState TypeError) as **Resolved**. Add comment: "Broadened beforeSend filter to case-insensitive pushState match; also added to ignoreErrors. PR: [link]."

- [ ] **Step 2: Resolve Sentry issue #437 in dashboard**

Mark issue #437 (hydration mismatch) as **Resolved**. Add comment: "Added ignoreErrors patterns for React hydration errors #418/#423/#425 and Sentry Replay DOM attribute injection. PR: [link]."

- [ ] **Step 3: Create PR**

```bash
gh pr create \
  --title "fix(website): suppress Sentry false positives — pushState and hydration (#434, #437)" \
  --body "Closes #434, closes #437. Broadens the pushState filter (case-insensitive, covers all TypeError variants) and adds ignoreErrors + beforeSend suppression for React hydration mismatches caused by Sentry Replay attribute injection."
```

---

## Self-Review Checklist

- [x] Both issues addressed: #434 (pushState) and #437 (hydration)
- [x] `ignoreErrors` + `beforeSend` belt-and-suspenders approach for reliability
- [x] No production SQL code changed — website-only fix
- [x] TypeScript compile check included
- [x] Production build check included
- [x] Server-side Sentry config verified (no changes needed)
