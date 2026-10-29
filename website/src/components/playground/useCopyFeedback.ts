'use client';
import { useCallback, useEffect, useRef, useState } from "react";

type CopyState = "idle" | "copied" | "failed";

/** Restartable feedback timer; disposal also ignores late clipboard promises. */
export function createCopyFeedback(setState: (state: CopyState) => void, ms = 2000) {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let disposed = false;
  const cancel = () => {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  };
  return {
    flash(state: Exclude<CopyState, "idle">) {
      if (disposed) return;
      cancel();
      setState(state);
      timer = setTimeout(() => {
        timer = null;
        setState("idle");
      }, ms);
    },
    dispose() {
      disposed = true;
      cancel();
    },
  };
}

export function useCopyFeedback(ms = 2000) {
  const [state, setState] = useState<CopyState>("idle");
  const feedback = useRef<ReturnType<typeof createCopyFeedback> | null>(null);
  useEffect(() => {
    const current = createCopyFeedback(setState, ms);
    feedback.current = current;
    return () => {
      current.dispose();
      feedback.current = null;
    };
  }, [ms]);
  const flash = useCallback((next: Exclude<CopyState, "idle">) => {
    feedback.current?.flash(next);
  }, []);
  return { copied: state === "copied", copyFailed: state === "failed", flash };
}
