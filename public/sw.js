self.addEventListener('push', function(event) {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(self.registration.showNotification(data.title || 'J4keIA', {
    body: data.body || '',
    icon: data.icon || '/icon.png',
    vibrate: [200, 100, 200],
    data: { url: 'https://j4kes.onrender.com' }
  }));
});
self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data.url));
});