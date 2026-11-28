// Runs the GoSQLX WebAssembly build off the main thread for the playground
// (see src/components/playground/WasmLoader.tsx). Go's runtime start-up and
// every parse/format/lint/analyze/highlight/transpile call take tens to
// hundreds of milliseconds on slow devices; doing that work here keeps the
// page responsive.
//
// Protocol (all messages are plain objects):
//   page -> worker  { type: "init", bytes: ArrayBuffer }   the gosqlx.wasm binary (transferred)
//   worker -> page  { type: "ready", functions: string[] } the gosqlx* functions Go registered
//   worker -> page  { type: "init-error", message }
//   page -> worker  { type: "call", id, fn, args }          fn is one of the registered functions
//   worker -> page  { type: "result", id, raw, us }         raw is the function's string result,
//                                                           us the call's duration in microseconds
//   worker -> page  { type: "error", id, message }
"use strict";

const READY_TIMEOUT_MS = 15000;
let functions = null;

function registeredFunctions() {
  return Object.keys(self).filter((name) => name.startsWith("gosqlx") && typeof self[name] === "function");
}

function waitForGo() {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (typeof self.gosqlxParse === "function") {
        resolve();
      } else if (Date.now() - start > READY_TIMEOUT_MS) {
        reject(new Error("WASM initialization timed out after 15 seconds"));
      } else {
        setTimeout(check, 10);
      }
    };
    check();
  });
}

async function init(bytes) {
  importScripts("/wasm/wasm_exec.js");
  const go = new self.Go();
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  // go.run() resolves only when the Go program exits, which it never does
  // (main blocks on select{}), so it is not awaited.
  go.run(instance);
  await waitForGo();
  functions = new Set(registeredFunctions());
  return [...functions];
}

self.onmessage = (event) => {
  const msg = event.data;
  if (msg.type === "init") {
    init(msg.bytes).then(
      (names) => self.postMessage({ type: "ready", functions: names }),
      (err) => self.postMessage({ type: "init-error", message: err instanceof Error ? err.message : String(err) }),
    );
    return;
  }
  if (msg.type === "call") {
    if (!functions || !functions.has(msg.fn)) {
      self.postMessage({ type: "error", id: msg.id, message: `${msg.fn} is not available in this WASM build` });
      return;
    }
    try {
      const start = performance.now();
      const raw = self[msg.fn](...msg.args);
      const us = (performance.now() - start) * 1000;
      self.postMessage({ type: "result", id: msg.id, raw, us });
    } catch (err) {
      self.postMessage({ type: "error", id: msg.id, message: err instanceof Error ? err.message : String(err) });
    }
  }
};
