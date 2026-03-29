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
    // pushState read-only — extensions (Vue/Redux DevTools) wrap history.pushState before our app loads.
    // Covers all variants: with/without object descriptor suffix, case differences.
    /Cannot assign to read only property ['"]?pushState['"]?/i,
    // React hydration mismatches triggered by Sentry Replay injecting DOM attributes.
    "Text content does not match server-rendered HTML",
    "Hydration failed because the server rendered HTML didn't match the client",
    "There was an error while hydrating",
    "Minified React error #418",
    "Minified React error #423",
    "Minified React error #425",
    // Chrome DevTools Protocol messages from extensions interacting with CodeMirror/Monaco.
    /Object Not Found Matching Id:\d+/,
  ],
  beforeSend(event) {
    const msg = event.exception?.values?.[0]?.value ?? "";

    // Belt-and-suspenders: also filter in beforeSend for events that bypass
    // ignoreErrors (e.g. unhandledrejection events, events with no exception value).
    //
    // 1. pushState read-only — extensions (Vue/Redux DevTools, privacy tools) wrap
    //    history.pushState before our app loads, making it read-only. Not
    //    reproducible without the extension. Covers all TypeError variants (#434).
    //
    // 2. React hydration errors — triggered by Sentry Replay injecting data-*
    //    attributes into the DOM. React compares server HTML (no attrs) with client
    //    HTML (Sentry attrs) → mismatch. Not a real app bug (#437).
    //
    // 3. "Object Not Found Matching Id:N" — Chrome DevTools Protocol messages from
    //    extensions interacting with CodeMirror/Monaco. Outside our code.
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
