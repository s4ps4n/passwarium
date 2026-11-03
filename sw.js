// Passwarium — service worker: приложение открывается и без сети.
// Стратегия: сеть сначала, при неудаче — кэш (свежая версия подтягивается при наличии связи).
const CACHE = 'passwarium-v3';
const ASSETS = [
  './', './index.html', './app.css', './app.js', './qr.js', './hash-wasm.js',
  './crypto-legacy.js', './manifest.webmanifest', './icon.svg',
  './fonts/inter-latin.woff2', './fonts/inter-cyrillic.woff2',
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.startsWith('/vault/')) return; // данные сейфа — всегда напрямую
  e.respondWith(
    fetch(e.request)
      .then(r => {
        if (r.ok) {
          const copy = r.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
        }
        return r;
      })
      .catch(() => caches.match(e.request).then(m => m || caches.match('./index.html')))
  );
});
