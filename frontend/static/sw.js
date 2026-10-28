// Security code and HTML always come from the network. Never persist admin pages,
// access responses, invitations or an obsolete crypto client in CacheStorage.
const CACHE_NAME = "nulltrace-assets-v29";
const ASSETS = ["/static/logo.png", "/static/css/style.css",
  "/static/fonts/Inter-Regular.woff2", "/static/fonts/Inter-SemiBold.woff2"];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys
    .filter(key => key.startsWith("nulltrace-") && key !== CACHE_NAME)
    .map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", event => {
  const request = event.request, url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || !ASSETS.includes(url.pathname)) return;
  event.respondWith(fetch(request).then(response => {
    if (response.ok) {
      const copy = response.clone();
      event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.put(request, copy)));
    }
    return response;
  }).catch(() => caches.match(request).then(cached => cached || new Response("", {status:503}))));
});
