import * as Sentry from "@sentry/nextjs";

const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;

// Shared regex for pushState read-only errors caused by browser extensions
// (Vue/Redux DevTools, privacy tools) wrapping history.pushState before our app loads.
const PUSHSTATE_REGEX = /Cannot assign to read only property ['"]?pushState['"]?/i;

Sentry.init({
  dsn,
  sendDefaultPii: false,
  tracesSampleRate: process.env.NODE_ENV === "development" ? 1.0 : 0.1,
  // Session Replay and structured logs are intentionally not enabled: they add
  // weight to every page's initial bundle. Error capture and tracing remain.
  enableLogs: false,
  // Suppress known-noisy error patterns that are not actionable app bugs.
  // These originate from browser extensions and Chrome DevTools Protocol messages.
  ignoreErrors: [
    // pushState read-only — covers all TypeError variants (#434).
    PUSHSTATE_REGEX,
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
    // 2. "Object Not Found Matching Id:N" — Chrome DevTools Protocol messages from
    //    extensions interacting with CodeMirror/Monaco. Outside our code.
    const isExtensionNoise =
      PUSHSTATE_REGEX.test(msg) ||
      msg.includes("Object Not Found Matching Id:");

    if (isExtensionNoise) {
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
