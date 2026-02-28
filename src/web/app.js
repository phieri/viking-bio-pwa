var pollTimer=null,sw=null,sub=null;
function poll(){
  fetch('/api/data').then(function(r){return r.json()}).then(function(d){
    document.getElementById('power').textContent=d.power?'ON':'OFF';
    document.getElementById('flame').textContent=d.flame?'ON':'OFF';
    document.getElementById('flame-card').className='card '+(d.flame?'flame-on':'flame-off');
    document.getElementById('fan').textContent=d.fan;
    document.getElementById('temp').textContent=d.temp;
    document.getElementById('err').textContent=d.err;
    document.getElementById('flame-hours').textContent=(d.flame_secs/3600).toFixed(1);
    const flameCheckbox = document.getElementById("flameSub");
    const errorCheckbox = document.getElementById("errorSub");
    const cleanCheckbox = document.getElementById("cleanSub");
    const pushBtn = document.getElementById("pushBtn");
    fetch('/api/subscribers').then(function(r){return r.json()}).then(function(s){
      if(typeof s.count !== 'undefined') document.getElementById('subscribers').textContent = s.count;
    }).catch(function(){});
    if(d.err>0){setStatus('Error detected: code '+d.err,'error')}
    else if(!d.valid){setStatus('No data from burner','stale')}
    else{setStatus('Live \u2014 last update: '+new Date().toLocaleTimeString(),'ok')}
  }).catch(function(){setStatus('Connection lost \u2014 retrying...','stale')});
}
function startPolling(){
  poll();
  if(pollTimer)clearInterval(pollTimer);
  pollTimer=setInterval(poll,2000);
}
function setStatus(msg,cls){
  var el=document.getElementById('status');
  el.textContent=msg;
  el.className='status '+cls;
}
function loadCountry(){
  fetch('/api/country').then(function(r){return r.json()}).then(function(d){
    document.getElementById('countryDisplay').textContent=d.country;
  }).catch(function(){});
}
async function togglePush(){
  if(!('serviceWorker' in navigator)||!('PushManager' in window)){
    alert('Push notifications not supported in this browser.');
    return;
  }
  if(sub){
    var ep=sub.endpoint;
    await sub.unsubscribe();
    sub=null;
    await fetch('/api/unsubscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoint:ep})});
    document.getElementById('pushBtn').textContent='Enable Push Notifications';
    document.getElementById('pushBtn').className='btn btn-push';
    return;
  }
  try{
    var r=await fetch('/api/vapid-public-key');
    var keyData=await r.json();
    sw=await navigator.serviceWorker.register('/sw.js');
    await navigator.serviceWorker.ready;
    var perm=await Notification.requestPermission();
    if(perm!=='granted'){alert('Notification permission denied.');return;}
    sub=await sw.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlBase64ToUint8Array(keyData.key)});
    var subJson=sub.toJSON();
    const flameCheckbox = document.getElementById("flameSub");
    const errorCheckbox = document.getElementById("errorSub");
    // Send flat fields the server expects: endpoint, p256dh, auth
    var body = {
      endpoint: subJson.endpoint || "",
      p256dh: (subJson.keys && subJson.keys.p256dh) ? subJson.keys.p256dh : "",
      auth:  (subJson.keys && subJson.keys.auth) ? subJson.keys.auth : "",
      prefs: { flame: !!flameCheckbox.checked, error: !!errorCheckbox.checked, clean: !!cleanCheckbox.checked }
    };
    await fetch('/api/subscribe', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    document.getElementById('pushBtn').textContent='Push Notifications ON';
    document.getElementById('pushBtn').className='btn btn-push subscribed';
  }catch(e){
    console.error('Push subscription failed:',e);
    alert('Push subscription failed: '+e.message);
  }
}

// Update or create subscription preferences without toggling subscription state.
async function updateSubscription(){
  const flameCheckbox = document.getElementById("flameSub");
  const errorCheckbox = document.getElementById("errorSub");
  const cleanCheckbox = document.getElementById("cleanSub");
  if(!('serviceWorker' in navigator)||!('PushManager' in window)){
    alert('Push notifications not supported in this browser.');
    return;
  }
  // If not subscribed yet, create subscription (togglePush will send prefs too)
  if(!sub){
    await togglePush();
    return;
  }
    try{
    var subJson = sub.toJSON();
    var body = {
      endpoint: subJson.endpoint || "",
      p256dh: (subJson.keys && subJson.keys.p256dh) ? subJson.keys.p256dh : "",
      auth:  (subJson.keys && subJson.keys.auth) ? subJson.keys.auth : "",
      prefs: { flame: !!flameCheckbox.checked, error: !!errorCheckbox.checked, clean: !!cleanCheckbox.checked }
    };
    await fetch('/api/subscribe', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    document.getElementById('pushBtn').textContent='Push Preferences Updated';
    setTimeout(function(){
      document.getElementById('pushBtn').textContent='Push Notifications ON';
    },1500);
  }catch(e){
    console.error('Updating subscription failed:',e);
    alert('Updating subscription failed: '+e.message);
  }
}
function urlBase64ToUint8Array(b64){
  var p=b64.replace(/-/g,'+').replace(/_/g,'/');
  while(p.length%4)p+='=';
  var r=atob(p);
  var o=new Uint8Array(r.length);
  for(var i=0;i<r.length;++i)o[i]=r.charCodeAt(i);
  return o;
}
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js').then(function(r){
    return r.pushManager.getSubscription();
  }).then(function(s){
    if(s){sub=s;document.getElementById('pushBtn').textContent='Push Notifications ON';document.getElementById('pushBtn').className='btn btn-push subscribed';}
  });
}
loadCountry();
startPolling();
