const CACHE_NAME = 'qr-shield-v4';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/scanner.html',
  '/history.html',
  '/report.html',
  '/about.html',
  '/offline.html',
  '/assets/css/style.css',
  '/assets/js/config.js',
  '/assets/js/utils.js',
  '/assets/js/analysis.js',
  '/assets/js/scanner.js',
  '/manifest.json'
];

// Install Event - cache core pages
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Service Worker] Pre-caching static assets');
      return cache.addAll(ASSETS_TO_CACHE);
    }).then(() => self.skipWaiting())
  );
});

// Activate Event - clear old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[Service Worker] Purging legacy cache:', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch Event - network-first fallback to cache, else offline page
self.addEventListener('fetch', (event) => {
  // Only cache GET requests
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);
  // Bypass caching/interception for backend API requests
  if (
    url.pathname.startsWith('/auth/') ||
    url.pathname.startsWith('/user/') ||
    url.pathname.startsWith('/scan') ||
    url.pathname.startsWith('/scans') ||
    url.pathname.startsWith('/report') ||
    url.pathname.startsWith('/admin/') ||
    url.hostname.includes('onrender.com') ||
    url.port === '5000'
  ) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        // Cache successful network responses dynamically
        return caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, networkResponse.clone());
          return networkResponse;
        });
      })
      .catch(() => {
        // Fallback to cache
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }
          // If request is an HTML page and fetch failed, load offline fallback page
          if (event.request.headers.get('accept') && event.request.headers.get('accept').includes('text/html')) {
            return caches.match('/offline.html');
          }
        });
      })
  );
});
