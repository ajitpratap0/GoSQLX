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
  beforeSend(event) {
    const msg = event.exception?.values?.[0]?.value ?? "";

    // Drop known browser-extension noise that cannot be fixed in app code:
    //
    // 1. "Cannot assign to read only property 'pushState'" — extensions
    //    (Vue/Redux DevTools, privacy tools) wrap history.pushState before our
    //    app loads, making it read-only. Not reproducible without the extension.
    //
    // 2. "Object Not Found Matching Id:N, MethodName:update" — Chrome DevTools
    //    Protocol messages from extensions interacting with CodeMirror/Monaco.
    //    The error originates outside our code and only affects a single session.
    if (
      msg.includes("Cannot assign to read only property 'pushState'") ||
      msg.includes("Object Not Found Matching Id:")
    ) {
      return null;
    }

    return event;
  },
});

export const onRouterTransitionStart = dsn
  ? Sentry.captureRouterTransitionStart
  : undefined;
