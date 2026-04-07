package server

import (
"context"
"crypto/tls"
"fmt"
iofs "io/fs"
"log"
"net"
"net/http"
"os"
"path/filepath"
"time"

proxy "github.com/phieri/viking-bio-pwa/proxy"
"github.com/phieri/viking-bio-pwa/proxy/internal/cert"
"github.com/phieri/viking-bio-pwa/proxy/internal/config"
"github.com/phieri/viking-bio-pwa/proxy/internal/push"
)

// Server wraps the HTTP(S) server with all its dependencies.
type Server struct {
cfg     *config.Config
handler *Handlers
httpSrv *http.Server
acmeSrv *http.Server
}

// New creates a Server.
func New(cfg *config.Config, pushMgr *push.Manager) *Server {
h := NewHandlers(cfg, pushMgr)
return &Server{cfg: cfg, handler: h}
}

// staticFS returns the filesystem to serve static files from.
func staticFS() http.FileSystem {
candidates := []string{
"public",
filepath.Join(filepath.Dir(os.Args[0]), "public"),
}
for _, p := range candidates {
if info, err := os.Stat(p); err == nil && info.IsDir() {
log.Printf("server: serving static files from disk: %s", p)
return http.Dir(p)
}
}
log.Printf("server: serving static files from embedded FS")
sub, _ := iofs.Sub(proxy.PublicFS, "public")
return http.FS(sub)
}

func (s *Server) buildMux() http.Handler {
mux := http.NewServeMux()
mux.HandleFunc("/api/data", methodGuard(http.MethodGet, s.handler.HandleGetData))
mux.HandleFunc("/api/vapid-public-key", methodGuard(http.MethodGet, s.handler.HandleGetVapidKey))
mux.HandleFunc("/api/subscribers", methodGuard(http.MethodGet, s.handler.HandleGetSubscribers))
mux.HandleFunc("/api/machine-data", methodGuard(http.MethodPost, jsonMiddleware(s.handler.HandleMachineData)))
mux.HandleFunc("/api/subscribe", methodGuard(http.MethodPost, jsonMiddleware(s.handler.HandleSubscribe)))
mux.HandleFunc("/api/unsubscribe", methodGuard(http.MethodPost, jsonMiddleware(s.handler.HandleUnsubscribe)))
mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
})
mux.Handle("/", http.FileServer(staticFS()))
return mux
}

func methodGuard(method string, next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
if r.Method != method {
writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
return
}
next(w, r)
}
}

func jsonMiddleware(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
ct := r.Header.Get("Content-Type")
if len(ct) < len("application/json") || ct[:len("application/json")] != "application/json" {
writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
return
}
next(w, r)
}
}

func (s *Server) Start(ctx context.Context) error {
mux := s.buildMux()
addr := fmt.Sprintf("[::]:%d", s.cfg.HTTPPort)
if s.cfg.DDNSSubdomain != "" && s.cfg.DDNSToken != "" {
domain := s.cfg.DDNSSubdomain + ".duckdns.org"
return s.startACME(ctx, mux, addr, domain)
}
if s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "" {
return s.startManualTLS(ctx, mux, addr)
}
return s.startHTTP(ctx, mux, addr)
}

func (s *Server) startHTTP(ctx context.Context, mux http.Handler, addr string) error {
srv := &http.Server{Addr: addr, Handler: mux}
s.httpSrv = srv
ln, err := net.Listen("tcp6", addr)
if err != nil {
ln, err = net.Listen("tcp", addr)
if err != nil {
return fmt.Errorf("listen %s: %w", addr, err)
}
}
log.Printf("Viking Bio Proxy listening on http://%s", addr)
logExtra(s.cfg)
go func() {
<-ctx.Done()
shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = srv.Shutdown(shutCtx)
}()
return srv.Serve(ln)
}

func (s *Server) startManualTLS(ctx context.Context, mux http.Handler, addr string) error {
tlsCert, err := tls.LoadX509KeyPair(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
if err != nil {
return fmt.Errorf("load TLS cert/key: %w", err)
}
srv := &http.Server{Addr: addr, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}}}
s.httpSrv = srv
ln, err := net.Listen("tcp6", addr)
if err != nil {
ln, err = net.Listen("tcp", addr)
if err != nil {
return fmt.Errorf("listen %s: %w", addr, err)
}
}
log.Printf("Viking Bio Proxy listening on https://%s (manual TLS)", addr)
logExtra(s.cfg)
go func() {
<-ctx.Done()
shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = srv.Shutdown(shutCtx)
}()
return srv.ServeTLS(ln, s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
}

func (s *Server) startACME(ctx context.Context, mux http.Handler, addr, domain string) error {
mgr, err := cert.NewManager(domain, s.cfg.ACMEEmail, s.cfg.ACMECertDir, s.cfg.ACMEStaging)
if err != nil {
return fmt.Errorf("cert manager: %w", err)
}
challengeSrv := &http.Server{
Addr:    fmt.Sprintf("[::]:%d", s.cfg.ACMEHTTPPort),
Handler: mgr.HTTPHandler(),
}
s.acmeSrv = challengeSrv
go func() {
log.Printf("cert: ACME HTTP-01 challenge server on :%d", s.cfg.ACMEHTTPPort)
if err := challengeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
log.Printf("cert: challenge server error: %v", err)
}
}()
srv := &http.Server{Addr: addr, Handler: mux, TLSConfig: mgr.TLSConfig()}
s.httpSrv = srv
ln, err := net.Listen("tcp6", addr)
if err != nil {
ln, err = net.Listen("tcp", addr)
if err != nil {
return fmt.Errorf("listen %s: %w", addr, err)
}
}
log.Printf("Viking Bio Proxy listening on https://%s:%d (Let's Encrypt)", domain, s.cfg.HTTPPort)
logExtra(s.cfg)
go func() {
<-ctx.Done()
shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = srv.Shutdown(shutCtx)
_ = challengeSrv.Shutdown(shutCtx)
}()
return srv.ServeTLS(ln, "", "")
}

func logExtra(cfg *config.Config) {
if cfg.PicoBaseURL != "" {
log.Printf("  Pico W base URL:   %s", cfg.PicoBaseURL)
}
if cfg.PicoVapidPublicKey != "" {
log.Printf("  Using Pico W VAPID key")
}
}
