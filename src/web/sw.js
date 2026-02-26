self.addEventListener('push',function(e){
  var d={title:'Viking Bio Alert',body:'Alert from burner',icon:'/icon.png'};
  try{d=e.data.json();}catch(ex){}
  e.waitUntil(self.registration.showNotification(d.title,{body:d.body,icon:d.icon||'/icon.png',badge:d.icon||'/icon.png',tag:'viking-bio-alert',requireInteraction:true}));
});
self.addEventListener('notificationclick',function(e){
  e.notification.close();
  e.waitUntil(clients.openWindow('/'));
});
self.addEventListener('install',function(e){self.skipWaiting();});
self.addEventListener('activate',function(e){e.waitUntil(clients.claim());});
