const CACHE = 'shield-shell-v5';
const SHELL = ['/', '/styles.css', '/landing.js', '/auth.html', '/auth.js', '/app.html', '/app.js', '/qr.js', '/recovery.html', '/recovery.js', '/data/recovery.json', '/docs.html', '/docs.js', '/integrations.html', '/integrations.js', '/openapi.yaml', '/manifest.webmanifest', '/icon.svg'];
self.addEventListener('install', (event) => event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL))));
self.addEventListener('activate', (event) => event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))));
self.addEventListener('fetch', (event) => {
  const requestUrl = new URL(event.request.url);
  if (event.request.method !== 'GET' || requestUrl.pathname.startsWith('/v1/')) return;
  event.respondWith(fetch(event.request).then((response) => {
    if (response.ok && requestUrl.origin === self.location.origin) caches.open(CACHE).then((cache) => cache.put(event.request, response.clone()));
    return response;
  }).catch(async () => (await caches.match(event.request)) ?? Response.error()));
});
