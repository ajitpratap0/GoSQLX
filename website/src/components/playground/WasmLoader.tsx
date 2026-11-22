'use client';
import { useState, useEffect, useRef } from "react";
import type { HighlightData, TextData } from "./bridgeTypes";

// The GoSQLX WASM build runs in a Web Worker (public/gosqlx-worker.js, which
// documents the message protocol). The page downloads the binary itself, so
// the <link rel="preload"> on /playground/ and the download progress bar keep
// working, then transfers the bytes to the worker. Every call is asynchronous;
// the worker answers calls in the order they were sent.

const WORKER_URL = "/gosqlx-worker.js";
const WASM_URL = "/wasm/gosqlx.wasm";

/** The playground API. Every call runs in the worker; failures reject with the error message. */
export interface GoSQLXApi {
  parse(sql: string, dialect?: string): Promise<unknown>;
  /** parse, plus the time the WASM call itself took in microseconds (excludes messaging). */
  parseTimed(sql: string, dialect?: string): Promise<{ result: unknown; us: number }>;
  /**
   * Rejects with the error message when the SQL cannot be formatted.
   * Unknown or omitted dialects use generic rules, as do parse, lint, analyze and highlight.
   */
  format(sql: string, dialect?: string): Promise<TextData>;
  lint(sql: string, dialect?: string): Promise<unknown>;
  analyze(sql: string, dialect?: string): Promise<unknown>;
  validate(sql: string, dialect?: string): Promise<{ valid: boolean; error?: string }>;
  /** Span offsets are UTF-16 code units (JavaScript string indices). */
  highlight(sql: string, dialect?: string): Promise<HighlightData>;
  /**
   * Rewrites SQL from one dialect to another.
   * Unlike the other calls, unknown source/target dialects reject with
   * `unsupported source|target dialect "x"`. An empty string means generic.
   */
  transpile(sql: string, from: string, to: string): Promise<TextData>;
}

export interface UseWasmResult {
  loading: boolean;
  ready: boolean;
  error: Error | null;
  api: GoSQLXApi | null;
  progress: number;
}

type WorkerReply =
  | { type: "ready"; functions: string[] }
  | { type: "init-error"; message: string }
  | { type: "result"; id: number; raw: string; us: number }
  | { type: "error"; id: number; message: string };

interface PendingCall {
  resolve(value: { raw: string; us: number }): void;
  reject(reason: Error): void;
}

function parseResult(raw: string): unknown {
  let result: unknown;
  try {
    result = JSON.parse(raw);
  } catch {
    // Not JSON: a plain text result (format() in WASM builds before it
    // returned {"result": ...}).
    return raw;
  }
  // Check for error objects OUTSIDE the try/catch so they propagate correctly
  if (result && typeof result === "object" && "error" in result && (result as Record<string, unknown>).error) {
    throw new Error(String((result as Record<string, unknown>).error));
  }
  return result;
}

async function downloadWasm(): Promise<ArrayBuffer> {
  const response = await fetch(WASM_URL);
  if (!response.ok) {
    throw new Error(`Failed to fetch WASM binary: HTTP ${response.status}`);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('text/html')) {
    throw new Error('SQL parser not available in preview deployments — visit gosqlx.dev for the live playground');
  }
  const contentLength = response.headers.get("content-length");
  const total = contentLength ? parseInt(contentLength, 10) : 0;

  if (!(total > 0 && response.body)) {
    // No content-length header: progress cannot be tracked.
    const buffer = await response.arrayBuffer();
    notifyProgress(1);
    return buffer;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    notifyProgress(Math.min(1, received / total));
  }
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  notifyProgress(1);
  return bytes.buffer;
}

let wasmPromise: Promise<GoSQLXApi> | null = null;
let progressListeners: Array<(progress: number) => void> = [];

function notifyProgress(progress: number) {
  for (const listener of progressListeners) {
    listener(progress);
  }
}

function startWorker(bytes: ArrayBuffer): Promise<GoSQLXApi> {
  return new Promise((resolveApi, rejectApi) => {
    const worker = new Worker(WORKER_URL);
    const pending = new Map<number, PendingCall>();
    let nextId = 0;
    let functions: ReadonlySet<string> = new Set();

    const failAll = (err: Error) => {
      for (const call of pending.values()) call.reject(err);
      pending.clear();
    };

    const call = (fn: string, args: string[]): Promise<{ raw: string; us: number }> => {
      if (!functions.has(fn)) {
        return Promise.reject(new Error(`${fn} is not available in this WASM build`));
      }
      return new Promise((resolve, reject) => {
        const id = nextId++;
        pending.set(id, { resolve, reject });
        worker.postMessage({ type: "call", id, fn, args });
      });
    };

    // Omits an empty dialect so the Go side sees the same arguments as before.
    const dialectArgs = (sql: string, dialect?: string) => (dialect ? [sql, dialect] : [sql]);
    const invoke = async (fn: string, args: string[]) => parseResult((await call(fn, args)).raw);

    const api: GoSQLXApi = {
      parse: (sql, dialect) => invoke("gosqlxParse", dialectArgs(sql, dialect)),
      async parseTimed(sql, dialect) {
        const { raw, us } = await call("gosqlxParse", dialectArgs(sql, dialect));
        return { result: parseResult(raw), us };
      },
      format: async (sql, dialect) => (await invoke("gosqlxFormat", dialectArgs(sql, dialect))) as TextData,
      lint: (sql, dialect) => invoke("gosqlxLint", dialectArgs(sql, dialect)),
      analyze: (sql, dialect) => invoke("gosqlxAnalyze", dialectArgs(sql, dialect)),
      validate: async (sql, dialect) =>
        (await invoke("gosqlxValidate", dialectArgs(sql, dialect))) as { valid: boolean; error?: string },
      highlight: async (sql, dialect) => (await invoke("gosqlxHighlight", dialectArgs(sql, dialect))) as HighlightData,
      transpile: async (sql, from, to) => (await invoke("gosqlxTranspile", [sql, from, to])) as TextData,
    };

    worker.onmessage = (event: MessageEvent<WorkerReply>) => {
      const msg = event.data;
      switch (msg.type) {
        case "ready":
          functions = new Set(msg.functions);
          resolveApi(api);
          return;
        case "init-error":
          worker.terminate();
          rejectApi(new Error(msg.message));
          return;
        case "result":
        case "error": {
          const entry = pending.get(msg.id);
          if (!entry) return;
          pending.delete(msg.id);
          if (msg.type === "result") entry.resolve({ raw: msg.raw, us: msg.us });
          else entry.reject(new Error(msg.message));
          return;
        }
      }
    };
    worker.onerror = (event: ErrorEvent) => {
      const err = new Error(event.message || "The SQL parser worker failed");
      failAll(err);
      rejectApi(err);
    };

    worker.postMessage({ type: "init", bytes }, [bytes]);
  });
}

export async function initWasm(): Promise<GoSQLXApi> {
  if (!wasmPromise) {
    wasmPromise = downloadWasm().then(startWorker);
  }
  return wasmPromise;
}

export function useWasm(enabled = true): UseWasmResult {
  const [loading, setLoading] = useState(enabled);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [api, setApi] = useState<GoSQLXApi | null>(null);
  const [progress, setProgress] = useState(0);
  const initialized = useRef(false);

  useEffect(() => {
    if (!enabled || initialized.current) return;
    initialized.current = true;
    setLoading(true);

    progressListeners.push(setProgress);

    initWasm()
      .then((wasmApi) => {
        setApi(wasmApi);
        setReady(true);
        setLoading(false);
      })
      .catch((err) => {
        setError(err instanceof Error ? err : new Error(String(err)));
        setLoading(false);
      });

    return () => {
      progressListeners = progressListeners.filter((l) => l !== setProgress);
    };
  }, [enabled]);

  return { loading, ready, error, api, progress };
}
