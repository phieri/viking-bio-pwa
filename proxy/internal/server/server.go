package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/phieri/viking-bio-pwa/proxy/internal/config"
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
		if ip16.Mask(net.CIDRMask(64, 128)).Equal(local16.Mask(net.CIDRMask(64, 128))) {
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
	ingestSrv  *tcpIngestServer
	notifyOnly bool
}

// New creates a Server. When notifyOnly is true the server skips the dashboard and
// restricts connections to the local network.
func New(cfg *config.Config, store *storage.Store, notifyOnly bool) *Server {
	h := NewHandlers(cfg)
	return &Server{
		cfg:        cfg,
		handler:    h,
		ingestSrv:  newTCPIngestServer(cfg, store, h),
		notifyOnly: notifyOnly,
	}
}

type apiRoute struct {
	path    string
	method  string
	handler http.HandlerFunc
}

func (s *Server) apiRoutes() []apiRoute {
	return []apiRoute{
		{path: "/api/data", method: http.MethodGet, handler: s.handler.HandleGetData},
		{path: "/api/metrics", method: http.MethodGet, handler: s.handler.HandleGetMetrics},
		{path: "/api/energy-price", method: http.MethodGet, handler: s.handler.HandleGetEnergyPrice},
	}
}

func (s *Server) registerAPIRoutes(mux *http.ServeMux) {
	for _, route := range s.apiRoutes() {
		mux.HandleFunc(route.path, methodGuard(route.method, route.handler))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
}

func (s *Server) buildMux() http.Handler {
	mux := http.NewServeMux()
	s.registerAPIRoutes(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
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

func (s *Server) Start(ctx context.Context) error {
	go func() {
		if err := s.ingestSrv.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("ingest: %v", err)
		}
	}()

	mux := s.buildMux()
	addr := fmt.Sprintf("[::]:%d", s.cfg.HTTPPort)
	if !s.notifyOnly {
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

func (s *Server) startHTTP(ctx context.Context, mux http.Handler, addr string) error {
	srv := &http.Server{Addr: addr, Handler: mux}
	s.httpSrv = srv
	ln, err := listen(addr)
	if err != nil {
		return err
	}
	log.Printf("Viking Bio Configurator listening on http://%s", addr)
	shutdownOnContext(ctx, srv)
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
	log.Printf("Viking Bio Configurator listening on https://%s (manual TLS)", addr)
	shutdownOnContext(ctx, srv)
	return srv.ServeTLS(ln, s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
}
