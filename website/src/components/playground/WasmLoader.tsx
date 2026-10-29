'use client';
import { useState, useEffect, useRef } from "react";
import type { HighlightData, TextData } from "./bridgeTypes";

// Type declarations for the Go WASM runtime
declare global {
  interface Window {
    Go: new () => {
      importObject: WebAssembly.Imports;
      run(instance: WebAssembly.Instance): Promise<void>;
    };
    gosqlxParse(sql: string, dialect?: string): string;
    gosqlxFormat(sql: string, dialect?: string): string;
    gosqlxLint(sql: string, dialect?: string): string;
    gosqlxAnalyze(sql: string, dialect?: string): string;
    gosqlxValidate(sql: string, dialect?: string): string;
    /** Absent in WASM binaries built before syntax highlighting was added. */
    gosqlxHighlight?: (sql: string, dialect?: string) => string;
    /** Absent in WASM binaries built before the Transpile tab was added. */
    gosqlxTranspile?: (sql: string, from: string, to: string) => string;
  }
}

export interface GoSQLXApi {
  parse(sql: string, dialect?: string): unknown;
  /**
   * Throws with the error message when the SQL cannot be formatted.
   * Unknown or omitted dialects use generic rules, as do parse, lint, analyze and highlight.
   */
  format(sql: string, dialect?: string): TextData;
  lint(sql: string, dialect?: string): unknown;
  analyze(sql: string, dialect?: string): unknown;
  validate(sql: string, dialect?: string): { valid: boolean; error?: string };
  /** Span offsets are UTF-16 code units (JavaScript string indices). Throws on failure. */
  highlight(sql: string, dialect?: string): HighlightData;
  /**
   * Rewrites SQL from one dialect to another. Throws on failure.
   * Unlike the other calls, unknown source/target dialects throw
   * `unsupported source|target dialect "x"`. An empty string means generic.
   */
  transpile(sql: string, from: string, to: string): TextData;
}

export interface UseWasmResult {
  loading: boolean;
  ready: boolean;
  error: Error | null;
  api: GoSQLXApi | null;
  progress: number;
}

function callAndParse(fn: (sql: string, dialect?: string) => string, sql: string, dialect?: string): unknown {
  return parseResult(dialect ? fn(sql, dialect) : fn(sql));
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

function loadScript(src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    // Check if already loaded
    if (window.Go) {
      resolve();
      return;
    }
    const script = document.createElement("script");
    script.src = src;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`Failed to load script: ${src}`));
    document.head.appendChild(script);
  });
}

let wasmPromise: Promise<GoSQLXApi> | null = null;
let progressListeners: Array<(progress: number) => void> = [];

function notifyProgress(progress: number) {
  for (const listener of progressListeners) {
    listener(progress);
  }
}

export async function initWasm(): Promise<GoSQLXApi> {
  if (wasmPromise) return wasmPromise;

  wasmPromise = (async () => {
    const base = "/";

    // Load wasm_exec.js which defines window.Go
    await loadScript(base + "wasm/wasm_exec.js");

    const go = new window.Go();

    const wasmPath = base + "wasm/gosqlx.wasm";

    // Fetch with progress tracking
    const response = await fetch(wasmPath);
    if (!response.ok) {
      throw new Error(`Failed to fetch WASM binary: HTTP ${response.status}`);
    }
    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('text/html')) {
      throw new Error('SQL parser not available in preview deployments — visit gosqlx.dev for the live playground');
    }
    const contentLength = response.headers.get("content-length");
    const total = contentLength ? parseInt(contentLength, 10) : 0;

    let result: WebAssembly.WebAssemblyInstantiatedSource;

    if (total > 0 && response.body) {
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

      const wasmBytes = new Uint8Array(received);
      let offset = 0;
      for (const chunk of chunks) {
        wasmBytes.set(chunk, offset);
        offset += chunk.length;
      }

      notifyProgress(1);
      result = await WebAssembly.instantiate(wasmBytes, go.importObject);
    } else {
      // Fallback: no content-length header, can't track progress
      const buffer = await response.arrayBuffer();
      notifyProgress(1);
      result = await WebAssembly.instantiate(buffer, go.importObject);
    }

    // Run the Go program (registers global functions).
    // go.run() never resolves (Go blocks with select{}), so don't await it.
    // The global functions are registered synchronously in main(), but we
    // need to yield to let the Go runtime initialize.
    go.run(result.instance);

    // Wait for the Go runtime to register the global functions
    await new Promise<void>((resolve, reject) => {
      const startTime = Date.now();
      const check = () => {
        if (typeof window.gosqlxParse === "function") {
          resolve();
        } else if (Date.now() - startTime > 15000) {
          reject(new Error("WASM initialization timed out after 15 seconds"));
        } else {
          setTimeout(check, 10);
        }
      };
      check();
    });

    const api: GoSQLXApi = {
      parse(sql: string, dialect?: string) {
        return callAndParse(window.gosqlxParse, sql, dialect);
      },
      format(sql: string, dialect?: string) {
        return callAndParse(window.gosqlxFormat, sql, dialect) as TextData;
      },
      lint(sql: string, dialect?: string) {
        return callAndParse(window.gosqlxLint, sql, dialect);
      },
      analyze(sql: string, dialect?: string) {
        return callAndParse(window.gosqlxAnalyze, sql, dialect);
      },
      validate(sql: string, dialect?: string) {
        return callAndParse(window.gosqlxValidate, sql, dialect) as { valid: boolean; error?: string };
      },
      highlight(sql: string, dialect?: string) {
        const fn = window.gosqlxHighlight;
        if (typeof fn !== "function") {
          throw new Error("gosqlxHighlight is not available in this WASM build");
        }
        return callAndParse(fn, sql, dialect) as HighlightData;
      },
      transpile(sql: string, from: string, to: string) {
        const fn = window.gosqlxTranspile;
        if (typeof fn !== "function") {
          throw new Error("gosqlxTranspile is not available in this WASM build");
        }
        return parseResult(fn(sql, from, to)) as TextData;
      },
    };

    return api;
  })();

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
