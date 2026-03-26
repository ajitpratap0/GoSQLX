'use client';
import { useState, useEffect, useRef } from "react";

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
  }
}

export interface GoSQLXApi {
  parse(sql: string, dialect?: string): unknown;
  format(sql: string, dialect?: string): { result: string };
  lint(sql: string, dialect?: string): unknown;
  analyze(sql: string, dialect?: string): unknown;
  validate(sql: string, dialect?: string): { valid: boolean; error?: string };
}

export interface UseWasmResult {
  loading: boolean;
  ready: boolean;
  error: Error | null;
  api: GoSQLXApi | null;
  progress: number;
}

function callAndParse(fn: (sql: string, dialect?: string) => string, sql: string, dialect?: string): unknown {
  const raw = dialect ? fn(sql, dialect) : fn(sql);
  let result: unknown;
  try {
    result = JSON.parse(raw);
  } catch {
    // Not JSON — plain text result (e.g., format() returns SQL text)
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
        notifyProgress(received / total);
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
        return callAndParse(window.gosqlxFormat, sql, dialect) as { result: string };
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
    };

    return api;
  })();

  return wasmPromise;
}

export function useWasm(): UseWasmResult {
  const [loading, setLoading] = useState(true);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [api, setApi] = useState<GoSQLXApi | null>(null);
  const [progress, setProgress] = useState(0);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

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
  }, []);

  return { loading, ready, error, api, progress };
}
