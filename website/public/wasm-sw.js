// Caches the playground WASM for offline use without ever pinning a stale binary.
// The binary lives at a fixed URL, so requests are network-first and revalidated
// (ETag, usually a cheap 304); the cached copy is only a fallback when offline.
const CACHE_NAME = 'gosqlx-wasm-v3';
const WASM_PATH = '/wasm/gosqlx.wasm';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) =>
      Promise.all(
        cacheNames
          .filter((name) => name.startsWith('gosqlx-wasm-') && name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (new URL(event.request.url).pathname !== WASM_PATH) return;
  event.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      fetch(event.request, { cache: 'no-cache' })
        .then((response) => {
          if (response.ok) cache.put(WASM_PATH, response.clone());
          return response;
        })
        .catch(() =>
          cache.match(WASM_PATH).then((cached) => cached || Response.error())
        )
    )
  );
});
