package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	iofs "io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	proxy "github.com/phieri/viking-bio-pwa/proxy"
	"github.com/phieri/viking-bio-pwa/proxy/internal/cert"
	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
	"github.com/phieri/viking-bio-pwa/proxy/internal/push"
	"github.com/phieri/viking-bio-pwa/proxy/internal/storage"
)

// localNetworks holds the private and loopback IP ranges used by localNetworkOnly.
var localNetworks []*net.IPNet

// ulaNetwork is the fc00::/7 entry in localNetworks, stored separately so it
// can be identified by pointer in isLocalNetwork without string comparison.
var ulaNetwork *net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("server: invalid local network CIDR " + cidr + ": " + err.Error())
		}
		if cidr == "fc00::/7" {
			ulaNetwork = network
		}
		localNetworks = append(localNetworks, network)
	}
}

// netInterfaceAddrs returns all addresses from up, non-loopback network
// interfaces. It is a variable to allow replacement in tests.
var netInterfaceAddrs = func() []net.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("server: failed to enumerate interfaces: %v", err)
		return nil
	}
	var addrs []net.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		addrs = append(addrs, ifaceAddrs...)
	}
	return addrs
}

// sharesPrefix64WithLocal returns true if ip (a ULA IPv6 address) shares the
// same /64 prefix as at least one of the proxy's own IPv6 interface addresses.
func sharesPrefix64WithLocal(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	for _, addr := range netInterfaceAddrs() {
		var localIP net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			localIP = v.IP
		case *net.IPAddr:
			localIP = v.IP
		}
		local16 := localIP.To16()
		if local16 == nil {
			continue
		}
		if bytes.Equal(ip16[:8], local16[:8]) {
			return true
		}
	}
	return false
}

// isLocalNetwork reports whether remoteAddr (host:port or bare host) is a
// loopback or private-network address. ULA (fc00::/7) addresses are only
// accepted when they share the same /64 prefix as a local interface address.
func isLocalNetwork(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range localNetworks {
		if network == ulaNetwork {
			if sharesPrefix64WithLocal(ip) {
				return true
			}
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// localNetworkOnly is an HTTP middleware that rejects requests whose remote
// address is not a loopback or private-network IP.
func localNetworkOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalNetwork(r.RemoteAddr) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Server wraps the HTTP(S) server with all its dependencies.
type Server struct {
	cfg        *config.Config
	handler    *Handlers
	httpSrv    *http.Server
	acmeSrv    *http.Server
	ingestSrv  *tcpIngestServer
	notifyOnly bool
	// OnReady is called with the dashboard URL once the server is accepting connections.
	OnReady func(url string)
}

// New creates a Server. When notifyOnly is true the server skips the dashboard,
// Let's Encrypt/ACME, and restricts connections to the local network.
func New(cfg *config.Config, pushMgr *push.Manager, store *storage.Store, notifyOnly bool) *Server {
	h := NewHandlers(pushMgr)
	return &Server{
		cfg:        cfg,
		handler:    h,
		ingestSrv:  newTCPIngestServer(cfg, store, h),
		notifyOnly: notifyOnly,
	}
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
	mux.HandleFunc("/api/subscribe", methodGuard(http.MethodPost, jsonMiddleware(s.handler.HandleSubscribe)))
	mux.HandleFunc("/api/unsubscribe", methodGuard(http.MethodPost, jsonMiddleware(s.handler.HandleUnsubscribe)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	if !s.notifyOnly {
		mux.Handle("/", http.FileServer(staticFS()))
	}
	var handler http.Handler = mux
	if s.notifyOnly {
		log.Println("server: notify-only mode – all routes restricted to local network")
		handler = localNetworkOnly(mux)
	}
	return handler
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
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
			return
		}
		next(w, r)
	}
}

func (s *Server) Start(ctx context.Context) error {
	go func() {
		if err := s.ingestSrv.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("ingest: %v", err)
		}
	}()

	mux := s.buildMux()
	addr := fmt.Sprintf("[::]:%d", s.cfg.HTTPPort)
	if !s.notifyOnly {
		if s.cfg.DDNSSubdomain != "" && s.cfg.DDNSToken != "" {
			domain := s.cfg.DDNSSubdomain + ".duckdns.org"
			return s.startACME(ctx, mux, addr, domain)
		}
		if s.cfg.TLSCertPath != "" && s.cfg.TLSKeyPath != "" {
			return s.startManualTLS(ctx, mux, addr)
		}
	}
	return s.startHTTP(ctx, mux, addr)
}

func listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp6", addr)
	if err == nil {
		return ln, nil
	}
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return ln, nil
}

func shutdownOnContext(ctx context.Context, servers ...*http.Server) {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range servers {
			if srv == nil {
				continue
			}
			_ = srv.Shutdown(shutCtx)
		}
	}()
}

// notifyReady calls OnReady in a goroutine if it is set.
// A recover() guard prevents a misbehaving callback from crashing the server.
func (s *Server) notifyReady(url string) {
	if s.OnReady == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("server: OnReady panic: %v", r)
			}
		}()
		s.OnReady(url)
	}()
}

func (s *Server) startHTTP(ctx context.Context, mux http.Handler, addr string) error {
	srv := &http.Server{Addr: addr, Handler: mux}
	s.httpSrv = srv
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	log.Printf("Viking Bio Proxy listening on http://%s", addr)
	shutdownOnContext(ctx, srv)
	s.notifyReady(fmt.Sprintf("http://localhost:%d", s.cfg.HTTPPort))
	return srv.Serve(ln)
}

func (s *Server) startManualTLS(ctx context.Context, mux http.Handler, addr string) error {
	tlsCert, err := tls.LoadX509KeyPair(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
	if err != nil {
		return fmt.Errorf("load TLS cert/key: %w", err)
	}
	srv := &http.Server{Addr: addr, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}}}
	s.httpSrv = srv
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	log.Printf("Viking Bio Proxy listening on https://%s (manual TLS)", addr)
	shutdownOnContext(ctx, srv)
	s.notifyReady(fmt.Sprintf("https://localhost:%d", s.cfg.HTTPPort))
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
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	log.Printf("Viking Bio Proxy listening on https://%s:%d (Let's Encrypt)", domain, s.cfg.HTTPPort)
	shutdownOnContext(ctx, srv, challengeSrv)
	s.notifyReady(fmt.Sprintf("https://%s:%d", domain, s.cfg.HTTPPort))
	return srv.ServeTLS(ln, "", "")
}
