const CACHE_NAME = "nulltrace-shell-v15";

const APP_SHELL = [
  "/",
  "/manifest.webmanifest",
  "/static/logo.png",
  "/static/css/style.css",
  "/static/js/access.js",
  "/static/js/app.js",
  "/static/js/pwa.js",
  "/static/js/modules/handshake.js",
  "/static/js/modules/group.js",
  "/static/js/modules/mls.js",
  "/static/js/modules/nacp.js",
  "/static/libs/libsodium-wrappers.bundle.js",
  "/static/libs/mlkem.bundle.js",
  "/static/fonts/Inter-Regular.woff2",
  "/static/fonts/Inter-SemiBold.woff2"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  const offline = () => new Response("", { status: 503, statusText: "Offline" });

  if (request.method !== "GET") return;
  if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/ws/")) return;

  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then(response => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put("/", copy));
          return response;
        })
        .catch(() => caches.match("/").then(cached => cached || new Response("<!doctype html><title>Offline</title>", {
          status: 503,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        })))
    );
    return;
  }

  if (url.pathname.startsWith("/static/js/") || url.pathname.startsWith("/static/css/") || url.pathname.startsWith("/static/libs/")) {
    event.respondWith(
      fetch(request)
        .then(response => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => caches.match(request, { ignoreSearch: false }).then(cached => cached || offline()))
    );
    return;
  }

  event.respondWith(
    caches.match(request, { ignoreSearch: false }).then(cached => {
      const network = fetch(request).then(response => {
        if (response && (response.ok || response.type === "opaque")) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
        }
        return response;
      }).catch(() => cached || offline());

      return cached || network;
    })
  );
});
