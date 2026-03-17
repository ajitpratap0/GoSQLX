'use client';
import { useEffect } from 'react';

export function ServiceWorkerRegister() {
  useEffect(() => {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/wasm-sw.js').catch(() => {});
    }
  }, []);
  return null;
}
