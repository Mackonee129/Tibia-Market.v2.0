// Service Worker v2 — sin caché, force-update automático
const SW_VERSION = "v2";

self.addEventListener('install', (e) => {
  console.log('[SW] Installing', SW_VERSION);
  self.skipWaiting(); // Activa inmediatamente sin esperar que se cierren tabs
});

self.addEventListener('activate', (e) => {
  console.log('[SW] Activating', SW_VERSION);
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(k => {
        console.log('[SW] Deleting cache:', k);
        return caches.delete(k);
      })))
      .then(() => self.clients.claim()) // Toma control de todas las tabs abiertas
  );
});

// Push-through: nunca cachear, siempre red
self.addEventListener('fetch', (e) => {
  e.respondWith(
    fetch(e.request).catch(() => {
      // Si no hay red y es navegación, mostrar mensaje offline
      if (e.request.mode === 'navigate') {
        return new Response(
          '<html><body style="background:#0E0D0A;color:#C9A227;font-family:monospace;padding:40px;text-align:center"><h2>⚔️ Sin conexión</h2><p>Tibia Market requiere internet. Vuelve cuando tengas conexión.</p></body></html>',
          { headers: { 'Content-Type': 'text/html' } }
        );
      }
    })
  );
});

// Recibir mensajes de la app (notificaciones)
self.addEventListener('message', (e) => {
  if (e.data?.type === 'SHOW_NOTIFICATION') {
    const { title, body, url, tag } = e.data;
    self.registration.showNotification(title, {
      body,
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      tag,
      data: { url }
    });
  }
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.openWindow(e.notification.data?.url || '/')
  );
});
