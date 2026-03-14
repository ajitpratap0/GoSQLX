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
}

function callAndParse(fn: (sql: string, dialect?: string) => string, sql: string, dialect?: string): unknown {
  const raw = dialect ? fn(sql, dialect) : fn(sql);
  // Try to parse as JSON first; if it fails, return as raw string
  // (e.g., format() returns plain SQL text, not JSON)
  try {
    const result = JSON.parse(raw);
    if (result && typeof result === "object" && "error" in result && result.error) {
      throw new Error(result.error);
    }
    return result;
  } catch {
    // Not JSON — return as-is (raw string result)
    return raw;
  }
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

export async function initWasm(): Promise<GoSQLXApi> {
  if (wasmPromise) return wasmPromise;

  wasmPromise = (async () => {
    const base = import.meta.env.BASE_URL;

    // Load wasm_exec.js which defines window.Go
    await loadScript(base + "wasm/wasm_exec.js");

    const go = new window.Go();

    const wasmPath = base + "wasm/gosqlx.wasm";
    const result = await WebAssembly.instantiateStreaming(fetch(wasmPath), go.importObject);

    // Run the Go program (registers global functions).
    // go.run() never resolves (Go blocks with select{}), so don't await it.
    // The global functions are registered synchronously in main(), but we
    // need to yield to let the Go runtime initialize.
    go.run(result.instance);

    // Wait for the Go runtime to register the global functions
    await new Promise<void>((resolve) => {
      const check = () => {
        if (typeof window.gosqlxParse === "function") {
          resolve();
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
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

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
  }, []);

  return { loading, ready, error, api };
}
