const WASM_CACHE = 'gosqlx-wasm-7fe84bbe';
const WASM_URL = '/wasm/gosqlx.wasm';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(WASM_CACHE).then((cache) => cache.add(WASM_URL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== WASM_CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.url.endsWith('gosqlx.wasm')) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((response) => {
          const clone = response.clone();
          caches.open(WASM_CACHE).then((cache) => cache.put(event.request, clone));
          return response;
        });
      })
    );
  }
});
