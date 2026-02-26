#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "http_server.h"
#include "push_manager.h"
#include "version.h"

// --- Embedded web files ---
// The dashboard HTML with SSE-based real-time updates and Web Push support
static const char INDEX_HTML[] =
"<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
"<meta name=\"theme-color\" content=\"#1a1a2e\">\n"
"<link rel=\"manifest\" href=\"/manifest.json\">\n"
"<title>Viking Bio 20 Dashboard</title>\n"
"<style>\n"
"*{box-sizing:border-box;margin:0;padding:0}\n"
"body{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#eee;min-height:100vh;padding:20px}\n"
"h1{text-align:center;color:#e94560;margin-bottom:24px;font-size:1.8em}\n"
".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;max-width:800px;margin:0 auto}\n"
".card{background:#16213e;border-radius:12px;padding:24px;text-align:center;border:1px solid #0f3460}\n"
".card .label{font-size:.8em;color:#aaa;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}\n"
".card .value{font-size:2em;font-weight:bold;color:#e94560}\n"
".card .unit{font-size:.9em;color:#888;margin-top:4px}\n"
".status{text-align:center;margin:16px auto;max-width:800px;padding:12px;border-radius:8px;font-size:.9em}\n"
".status.ok{background:#0f3460;color:#4ecdc4}\n"
".status.error{background:#3d0000;color:#ff6b6b}\n"
".status.stale{background:#2d2d00;color:#ffd93d}\n"
".status.connecting{background:#1a1a2e;color:#aaa}\n"
".btn{display:inline-block;padding:10px 20px;border-radius:8px;border:none;cursor:pointer;font-size:.9em;margin:4px}\n"
".btn-push{background:#0f3460;color:#e94560;border:1px solid #e94560}\n"
".btn-push:hover{background:#1a3a6e}\n"
".btn-push.subscribed{background:#0d3d2e;color:#4ecdc4;border-color:#4ecdc4}\n"
".actions{text-align:center;margin:16px auto;max-width:800px}\n"
".flame-on .value{color:#ff6b35}\n"
".flame-off .value{color:#555}\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<h1>&#9919; Viking Bio 20</h1>\n"
"<div class=\"status connecting\" id=\"status\">Connecting...</div>\n"
"<div class=\"grid\">\n"
"<div class=\"card\" id=\"flame-card\">\n"
"<div class=\"label\">Flame</div>\n"
"<div class=\"value\" id=\"flame\">--</div>\n"
"<div class=\"unit\">status</div>\n"
"</div>\n"
"<div class=\"card\">\n"
"<div class=\"label\">Fan Speed</div>\n"
"<div class=\"value\" id=\"fan\">--</div>\n"
"<div class=\"unit\">%</div>\n"
"</div>\n"
"<div class=\"card\">\n"
"<div class=\"label\">Temperature</div>\n"
"<div class=\"value\" id=\"temp\">--</div>\n"
"<div class=\"unit\">&deg;C</div>\n"
"</div>\n"
"<div class=\"card\">\n"
"<div class=\"label\">Error Code</div>\n"
"<div class=\"value\" id=\"err\">--</div>\n"
"<div class=\"unit\">code</div>\n"
"</div>\n"
"</div>\n"
"<div class=\"actions\">\n"
"<button class=\"btn btn-push\" id=\"pushBtn\" onclick=\"togglePush()\">Enable Push Notifications</button>\n"
"</div>\n"
"<script>\n"
"var es=null,sw=null,sub=null;\n"
"function connect(){\n"
"  es=new EventSource('/data');\n"
"  es.onopen=function(){setStatus('Connected','ok')};\n"
"  es.onmessage=function(e){\n"
"    try{\n"
"      var d=JSON.parse(e.data);\n"
"      document.getElementById('flame').textContent=d.flame?'ON':'OFF';\n"
"      document.getElementById('flame-card').className='card '+(d.flame?'flame-on':'flame-off');\n"
"      document.getElementById('fan').textContent=d.fan;\n"
"      document.getElementById('temp').textContent=d.temp;\n"
"      document.getElementById('err').textContent=d.err;\n"
"      if(d.err>0){setStatus('Error detected: code '+d.err,'error')}\n"
"      else if(!d.valid){setStatus('No data from burner','stale')}\n"
"      else{setStatus('Live \\u2014 last update: '+new Date().toLocaleTimeString(),'ok')}\n"
"    }catch(ex){}\n"
"  };\n"
"  es.onerror=function(){setStatus('Connection lost \\u2014 reconnecting...','stale');setTimeout(connect,3000)};\n"
"}\n"
"function setStatus(msg,cls){\n"
"  var el=document.getElementById('status');\n"
"  el.textContent=msg;\n"
"  el.className='status '+cls;\n"
"}\n"
"async function togglePush(){\n"
"  if(!('serviceWorker' in navigator)||!('PushManager' in window)){\n"
"    alert('Push notifications not supported in this browser.');\n"
"    return;\n"
"  }\n"
"  if(sub){\n"
"    var ep=sub.endpoint;\n"
"    await sub.unsubscribe();\n"
"    sub=null;\n"
"    await fetch('/unsubscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({endpoint:ep})});\n"
"    document.getElementById('pushBtn').textContent='Enable Push Notifications';\n"
"    document.getElementById('pushBtn').className='btn btn-push';\n"
"    return;\n"
"  }\n"
"  try{\n"
"    var r=await fetch('/vapid-public-key');\n"
"    var keyData=await r.json();\n"
"    sw=await navigator.serviceWorker.register('/sw.js');\n"
"    await navigator.serviceWorker.ready;\n"
"    var perm=await Notification.requestPermission();\n"
"    if(perm!=='granted'){alert('Notification permission denied.');return;}\n"
"    sub=await sw.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlBase64ToUint8Array(keyData.key)});\n"
"    var subJson=sub.toJSON();\n"
"    await fetch('/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(subJson)});\n"
"    document.getElementById('pushBtn').textContent='Push Notifications ON';\n"
"    document.getElementById('pushBtn').className='btn btn-push subscribed';\n"
"  }catch(e){\n"
"    console.error('Push subscription failed:',e);\n"
"    alert('Push subscription failed: '+e.message);\n"
"  }\n"
"}\n"
"function urlBase64ToUint8Array(b64){\n"
"  var p=b64.replace(/-/g,'+').replace(/_/g,'/');\n"
"  while(p.length%4)p+='=';\n"
"  var r=atob(p);\n"
"  var o=new Uint8Array(r.length);\n"
"  for(var i=0;i<r.length;++i)o[i]=r.charCodeAt(i);\n"
"  return o;\n"
"}\n"
"if('serviceWorker' in navigator){\n"
"  navigator.serviceWorker.register('/sw.js').then(function(r){\n"
"    return r.pushManager.getSubscription();\n"
"  }).then(function(s){\n"
"    if(s){sub=s;document.getElementById('pushBtn').textContent='Push Notifications ON';document.getElementById('pushBtn').className='btn btn-push subscribed';}\n"
"  });\n"
"}\n"
"connect();\n"
"</script>\n"
"</body>\n"
"</html>\n";

static const char SW_JS[] =
"self.addEventListener('push',function(e){\n"
"  var d={title:'Viking Bio Alert',body:'Alert from burner',icon:'/icon.png'};\n"
"  try{d=e.data.json();}catch(ex){}\n"
"  e.waitUntil(self.registration.showNotification(d.title,{body:d.body,icon:d.icon||'/icon.png',badge:d.icon||'/icon.png',tag:'viking-bio-alert',requireInteraction:true}));\n"
"});\n"
"self.addEventListener('notificationclick',function(e){\n"
"  e.notification.close();\n"
"  e.waitUntil(clients.openWindow('/'));\n"
"});\n"
"self.addEventListener('install',function(e){self.skipWaiting();});\n"
"self.addEventListener('activate',function(e){e.waitUntil(clients.claim());});\n";

static const char MANIFEST_JSON[] =
"{\n"
"  \"name\": \"Viking Bio 20 Dashboard\",\n"
"  \"short_name\": \"VikingBio\",\n"
"  \"description\": \"Real-time dashboard for Viking Bio 20 burner\",\n"
"  \"start_url\": \"/\",\n"
"  \"display\": \"standalone\",\n"
"  \"background_color\": \"#1a1a2e\",\n"
"  \"theme_color\": \"#1a1a2e\",\n"
"  \"icons\": [\n"
"    {\"src\": \"/icon.png\", \"sizes\": \"192x192\", \"type\": \"image/png\"}\n"
"  ]\n"
"}\n";

// --- HTTP connection state ---
typedef enum {
	CONN_IDLE,
	CONN_HTTP,
	CONN_SSE,
} conn_type_t;

typedef struct http_conn {
	struct tcp_pcb *pcb;
	conn_type_t type;
	uint8_t req_buf[512];
	size_t req_len;
	bool headers_sent;
	struct http_conn *next;
} http_conn_t;

// SSE connections list
static http_conn_t *sse_connections = NULL;
static http_conn_t *all_connections = NULL;
static struct tcp_pcb *server_pcb = NULL;

// Last broadcast data for new SSE connections
static char last_sse_event[128] = "";

// --- Base64url encoding ---
static const char b64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_size) {
	size_t out_len = 0;
	size_t i;
	for (i = 0; i + 2 < len; i += 3) {
		if (out_len + 4 >= out_size) break;
		out[out_len++] = b64url_chars[(data[i] >> 2) & 0x3F];
		out[out_len++] = b64url_chars[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
		out[out_len++] = b64url_chars[((data[i+1] & 0xF) << 2) | ((data[i+2] >> 6) & 0x3)];
		out[out_len++] = b64url_chars[data[i+2] & 0x3F];
	}
	if (i < len && out_len + 3 < out_size) {
		if (len - i == 1) {
			out[out_len++] = b64url_chars[(data[i] >> 2) & 0x3F];
			out[out_len++] = b64url_chars[(data[i] & 0x3) << 4];
		} else {
			out[out_len++] = b64url_chars[(data[i] >> 2) & 0x3F];
			out[out_len++] = b64url_chars[((data[i] & 0x3) << 4) | ((data[i+1] >> 4) & 0xF)];
			out[out_len++] = b64url_chars[(data[i+1] & 0xF) << 2];
		}
	}
	if (out_len < out_size) out[out_len] = '\0';
	return out_len;
}

/**
 * Extract a JSON string value for the given key from a JSON object string.
 * Finds the first occurrence of "key":"value" and copies value into out[0..out_size-1].
 * Returns true on success, false if key not found or value too long.
 * All strchr return values are checked before dereferencing.
 */
static bool json_extract_string(const char *json, const char *key,
                                 char *out, size_t out_size) {
	if (!json || !key || !out || out_size == 0) return false;
	out[0] = '\0';

	char search[64];
	snprintf(search, sizeof(search), "\"%s\":", key);
	const char *p = strstr(json, search);
	if (!p) return false;

	// Advance past the key and colon
	p += strlen(search);

	// Skip whitespace
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

	// Expect opening quote
	if (*p != '"') return false;
	p++;  // skip opening quote

	// Find closing quote (not preceded by backslash)
	const char *end = strchr(p, '"');
	if (!end) return false;

	size_t val_len = (size_t)(end - p);
	if (val_len >= out_size) return false;

	memcpy(out, p, val_len);
	out[val_len] = '\0';
	return true;
}

// --- HTTP helpers ---
static void close_conn(http_conn_t *conn) {
	if (!conn) return;
	// Remove from SSE list
	http_conn_t **prev = &sse_connections;
	while (*prev) {
		if (*prev == conn) { *prev = conn->next; break; }
		prev = &(*prev)->next;
	}
	// Remove from all connections list
	prev = &all_connections;
	while (*prev) {
		if (*prev == conn) { *prev = conn->next; break; }
		prev = &(*prev)->next;
	}
	if (conn->pcb) {
		tcp_arg(conn->pcb, NULL);
		tcp_close(conn->pcb);
		conn->pcb = NULL;
	}
	free(conn);
}

static err_t send_string(struct tcp_pcb *pcb, const char *str) {
	if (!pcb || !str) return ERR_ARG;
	size_t len = strlen(str);
	if (len == 0) return ERR_OK;
	// Check send buffer
	if (tcp_sndbuf(pcb) < len) return ERR_MEM;
	return tcp_write(pcb, str, (u16_t)len, TCP_WRITE_FLAG_COPY);
}

static void send_http_response(struct tcp_pcb *pcb, int code, const char *content_type,
                                const char *body, size_t body_len) {
	char header[256];
	const char *code_str = (code == 200) ? "200 OK" :
	                       (code == 404) ? "404 Not Found" :
	                       (code == 400) ? "400 Bad Request" :
	                       (code == 405) ? "405 Method Not Allowed" : "500 Internal Server Error";
	snprintf(header, sizeof(header),
	         "HTTP/1.1 %s\r\n"
	         "Content-Type: %s\r\n"
	         "Content-Length: %zu\r\n"
	         "Connection: close\r\n"
	         "Access-Control-Allow-Origin: *\r\n"
	         "\r\n",
	         code_str, content_type, body_len);
	send_string(pcb, header);
	if (body && body_len > 0) {
		tcp_write(pcb, body, (u16_t)body_len, TCP_WRITE_FLAG_COPY);
	}
	tcp_output(pcb);
}

// --- Parse HTTP request line ---
static void handle_request(http_conn_t *conn) {
	char *req = (char *)conn->req_buf;
	req[conn->req_len < 511 ? conn->req_len : 511] = '\0';

	// Extract method and path
	char method[8] = {0};
	char path[256] = {0};
	sscanf(req, "%7s %255s", method, path);

	// Strip query string
	char *q = strchr(path, '?');
	if (q) *q = '\0';

	// GET /
	if (strcmp(method, "GET") == 0 && strcmp(path, "/") == 0) {
		send_http_response(conn->pcb, 200, "text/html; charset=utf-8",
		                   INDEX_HTML, strlen(INDEX_HTML));
		close_conn(conn);
		return;
	}

	// GET /sw.js
	if (strcmp(method, "GET") == 0 && strcmp(path, "/sw.js") == 0) {
		send_http_response(conn->pcb, 200, "application/javascript; charset=utf-8",
		                   SW_JS, strlen(SW_JS));
		close_conn(conn);
		return;
	}

	// GET /manifest.json
	if (strcmp(method, "GET") == 0 && strcmp(path, "/manifest.json") == 0) {
		send_http_response(conn->pcb, 200, "application/manifest+json; charset=utf-8",
		                   MANIFEST_JSON, strlen(MANIFEST_JSON));
		close_conn(conn);
		return;
	}

	// GET /vapid-public-key
	if (strcmp(method, "GET") == 0 && strcmp(path, "/vapid-public-key") == 0) {
		char key_b64[96] = {0};
		http_server_get_vapid_public_key(key_b64, sizeof(key_b64));
		char body[128];
		snprintf(body, sizeof(body), "{\"key\":\"%s\"}", key_b64);
		send_http_response(conn->pcb, 200, "application/json; charset=utf-8",
		                   body, strlen(body));
		close_conn(conn);
		return;
	}

	// GET /data - SSE endpoint
	if (strcmp(method, "GET") == 0 && strcmp(path, "/data") == 0) {
		const char *sse_headers =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/event-stream\r\n"
			"Cache-Control: no-cache\r\n"
			"Connection: keep-alive\r\n"
			"Access-Control-Allow-Origin: *\r\n"
			"\r\n";
		send_string(conn->pcb, sse_headers);
		// Send last known data immediately
		if (last_sse_event[0]) {
			send_string(conn->pcb, last_sse_event);
		}
		tcp_output(conn->pcb);
		conn->type = CONN_SSE;
		// Add to SSE connections
		conn->next = sse_connections;
		sse_connections = conn;
		return;  // Don't close - keep alive for SSE
	}

	// POST /subscribe
	if (strcmp(method, "POST") == 0 && strcmp(path, "/subscribe") == 0) {
		// Find JSON body after headers
		char *body_start = strstr(req, "\r\n\r\n");
		if (body_start) {
			body_start += 4;
			char endpoint[PUSH_MAX_ENDPOINT_LEN] = {0};
			char p256dh[PUSH_MAX_KEY_LEN] = {0};
			char auth[PUSH_MAX_AUTH_LEN] = {0};

			json_extract_string(body_start, "endpoint", endpoint, sizeof(endpoint));
			json_extract_string(body_start, "p256dh", p256dh, sizeof(p256dh));
			json_extract_string(body_start, "auth", auth, sizeof(auth));

			if (endpoint[0]) {
				bool ok = push_manager_add_subscription(endpoint, p256dh, auth);
				const char *resp = ok ? "{\"status\":\"ok\"}" : "{\"status\":\"full\"}";
				send_http_response(conn->pcb, 200, "application/json; charset=utf-8",
				                   resp, strlen(resp));
			} else {
				send_http_response(conn->pcb, 400, "application/json; charset=utf-8",
				                   "{\"error\":\"missing endpoint\"}", 26);
			}
		} else {
			send_http_response(conn->pcb, 400, "application/json; charset=utf-8",
			                   "{\"error\":\"no body\"}", 19);
		}
		close_conn(conn);
		return;
	}

	// POST /unsubscribe
	if (strcmp(method, "POST") == 0 && strcmp(path, "/unsubscribe") == 0) {
		char *body_start = strstr(req, "\r\n\r\n");
		if (body_start) {
			body_start += 4;
			char endpoint[PUSH_MAX_ENDPOINT_LEN] = {0};
			if (json_extract_string(body_start, "endpoint", endpoint, sizeof(endpoint))) {
				push_manager_remove_subscription(endpoint);
			}
		}
		send_http_response(conn->pcb, 200, "application/json; charset=utf-8",
		                   "{\"status\":\"ok\"}", 15);
		close_conn(conn);
		return;
	}

	// 404
	send_http_response(conn->pcb, 404, "text/plain", "Not Found", 9);
	close_conn(conn);
}

// --- lwIP callbacks ---
static err_t conn_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
	http_conn_t *conn = (http_conn_t *)arg;
	if (!conn) return ERR_OK;

	if (p == NULL || err != ERR_OK) {
		// Connection closed by client
		close_conn(conn);
		return ERR_OK;
	}

	// Accumulate request data
	size_t to_copy = p->tot_len;
	if (conn->req_len + to_copy > sizeof(conn->req_buf) - 1) {
		to_copy = sizeof(conn->req_buf) - 1 - conn->req_len;
	}
	pbuf_copy_partial(p, conn->req_buf + conn->req_len, (u16_t)to_copy, 0);
	conn->req_len += to_copy;
	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);

	// Check if we have a complete HTTP request (ends with \r\n\r\n)
	conn->req_buf[conn->req_len] = '\0';
	if (strstr((char *)conn->req_buf, "\r\n\r\n")) {
		handle_request(conn);
	}

	return ERR_OK;
}

static void conn_err(void *arg, err_t err) {
	(void)err;
	http_conn_t *conn = (http_conn_t *)arg;
	if (!conn) return;
	conn->pcb = NULL;  // PCB already freed by lwIP
	close_conn(conn);
}

static err_t conn_accept(void *arg, struct tcp_pcb *new_pcb, err_t err) {
	(void)arg;
	if (err != ERR_OK || !new_pcb) return ERR_VAL;

	http_conn_t *conn = (http_conn_t *)calloc(1, sizeof(http_conn_t));
	if (!conn) {
		tcp_abort(new_pcb);
		return ERR_MEM;
	}

	conn->pcb = new_pcb;
	conn->type = CONN_HTTP;
	conn->req_len = 0;

	// Add to all connections
	conn->next = all_connections;
	all_connections = conn;

	tcp_arg(new_pcb, conn);
	tcp_recv(new_pcb, conn_recv);
	tcp_err(new_pcb, conn_err);
	tcp_setprio(new_pcb, TCP_PRIO_MIN);

	return ERR_OK;
}

// --- Public API ---
bool http_server_init(void) {
	server_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
	if (!server_pcb) return false;

	err_t err = tcp_bind(server_pcb, IP_ANY_TYPE, HTTP_SERVER_PORT);
	if (err != ERR_OK) {
		tcp_close(server_pcb);
		server_pcb = NULL;
		return false;
	}

	server_pcb = tcp_listen_with_backlog(server_pcb, 4);
	if (!server_pcb) return false;

	tcp_accept(server_pcb, conn_accept);
	printf("HTTP server listening on port %d\n", HTTP_SERVER_PORT);
	return true;
}

void http_server_poll(void) {
	// lwIP polling is handled by cyw43_arch_poll() in main loop
}

void http_server_broadcast_data(const viking_bio_data_t *data) {
	if (!data) return;

	// Build SSE event
	char event[128];
	int len = snprintf(event, sizeof(event),
	                   "data:{\"flame\":%s,\"fan\":%d,\"temp\":%d,\"err\":%d,\"valid\":%s}\n\n",
	                   data->flame_detected ? "true" : "false",
	                   data->fan_speed,
	                   data->temperature,
	                   data->error_code,
	                   data->valid ? "true" : "false");
	if (len <= 0 || len >= (int)sizeof(event)) return;

	// Cache for new connections
	memcpy(last_sse_event, event, len + 1);

	// Send to all SSE connections
	http_conn_t *conn = sse_connections;
	http_conn_t *next;
	while (conn) {
		next = conn->next;
		if (conn->pcb && tcp_sndbuf(conn->pcb) >= (size_t)len) {
			err_t err = tcp_write(conn->pcb, event, (u16_t)len, TCP_WRITE_FLAG_COPY);
			if (err == ERR_OK) {
				tcp_output(conn->pcb);
			}
		}
		conn = next;
	}
}

size_t http_server_get_vapid_public_key(char *buf, size_t buf_size) {
	uint8_t key_raw[65];
	if (!push_manager_get_vapid_public_key(key_raw)) return 0;
	return base64url_encode(key_raw, 65, buf, buf_size);
}
