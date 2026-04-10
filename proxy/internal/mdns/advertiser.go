package mdns

import (
	"log"
	"net"
	"os"

	"github.com/grandcat/zeroconf"
)

const serviceType = "_viking-bio._tcp"

// Advertiser publishes the proxy as a DNS-SD service.
type Advertiser struct {
	server *zeroconf.Server
}

// isLinkLocalIPv6 returns true if ip is an IPv6 link-local address (fe80::/10).
func isLinkLocalIPv6(ip6 net.IP) bool {
	return ip6[0] == 0xfe && (ip6[1]&0xc0) == 0x80
}

// isLocalIPv6 returns true if ip is a ULA (fc00::/7) or link-local (fe80::/10) IPv6 address.
// These are the address ranges that should be used for local network discovery.
func isLocalIPv6(ip net.IP) bool {
	ip6 := ip.To16()
	if ip6 == nil || ip.To4() != nil {
		return false // skip IPv4
	}
	// Link-local: fe80::/10 — first 10 bits are 1111111010
	if isLinkLocalIPv6(ip6) {
		return true
	}
	// ULA: fc00::/7 — first 7 bits are 1111110 (covers fc00:: and fd00::)
	if (ip6[0] & 0xfe) == 0xfc {
		return true
	}
	return false
}

// collectLocalIPv6Addrs enumerates all up, non-loopback network interfaces and
// returns their ULA (fc00::/7) and link-local (fe80::/10) IPv6 addresses.
// ULA addresses appear first, followed by link-local addresses.
func collectLocalIPv6Addrs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("mdns: failed to enumerate interfaces: %v", err)
		return nil
	}
	var ula, linklocal []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if !isLocalIPv6(ip) {
				continue
			}
			ip6 := ip.To16()
			// Separate ULA from link-local for ordering (ULA first).
			if isLinkLocalIPv6(ip6) {
				linklocal = append(linklocal, ip.String())
			} else {
				ula = append(ula, ip.String())
			}
		}
	}
	return append(ula, linklocal...)
}

// Start registers the DNS-SD service record on the given port with the given name.
//
// When ULA (fc00::/7) or link-local (fe80::/10) IPv6 addresses are found on
// any local interface, only those addresses are advertised via
// zeroconf.RegisterProxy so that Pico devices discover a local-only address.
// ULA addresses are listed before link-local.  If no such addresses are
// available the function falls back to zeroconf.Register (host=nil), which
// advertises all interface addresses, and logs a warning.
func (a *Advertiser) Start(port int, name string) {
	localAddrs := collectLocalIPv6Addrs()

	var err error
	if len(localAddrs) > 0 {
		// Advertise only the local-only IPv6 addresses so Pico devices do not
		// pick up global/public addresses through mDNS discovery.
		hostname, herr := os.Hostname()
		if herr != nil || hostname == "" {
			hostname = "viking-bio-proxy"
		}
		log.Printf("mdns: advertising local-only IPv6 addresses: %v", localAddrs)
		a.server, err = zeroconf.RegisterProxy(
			name,
			serviceType,
			"local.",
			port,
			hostname,
			localAddrs,
			[]string{"path=/api/data"},
			nil,
		)
	} else {
		// No ULA/link-local IPv6 found — fall back to advertising all addresses.
		log.Printf("mdns: warning: no ULA/link-local IPv6 addresses found; advertising all addresses")
		a.server, err = zeroconf.Register(
			name,
			serviceType,
			"local.",
			port,
			[]string{"path=/api/data"},
			nil,
		)
	}

	if err != nil {
		log.Printf("mdns: failed to register: %v", err)
		return
	}
	log.Printf("mdns: published %s \"%s\" on port %d", serviceType, name, port)
}

// Stop unregisters the DNS-SD service.
func (a *Advertiser) Stop() {
	if a.server != nil {
		a.server.Shutdown()
		a.server = nil
		log.Println("mdns: stopped")
	}
}
