/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package mdns

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

const serviceType = "_viking-bio._tcp"
const announceInterval = 30 * time.Second

// Advertiser publishes the configurator as a DNS-SD service and periodically
// re-announces it to keep the service visible even when the Pico remains idle.
type Advertiser struct {
	mu     sync.Mutex
	server *zeroconf.Server
	stopCh chan struct{}
}

// isLinkLocalIPv6 returns true if ip is an IPv6 link-local address (fe80::/10).
func isLinkLocalIPv6(ip6 net.IP) bool {
	if len(ip6) < 2 {
		return false
	}
	return ip6[0] == 0xfe && (ip6[1]&0xc0) == 0x80
}

// isLocalIPv6 returns true if ip is a ULA (fc00::/7) or link-local (fe80::/10) IPv6 address.
// These are the address ranges that should be used for local network discovery.
func isLocalIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}
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

func publishService(port int, name string, localAddrs []string) (*zeroconf.Server, error) {
	if len(localAddrs) > 0 {
		hostname, herr := os.Hostname()
		if herr != nil || hostname == "" {
			hostname = "viking-bio-configurator"
		}
		log.Printf("mdns: advertising local-only IPv6 addresses: %v", localAddrs)
		return zeroconf.RegisterProxy(
			name,
			serviceType,
			"local.",
			port,
			hostname,
			localAddrs,
			nil,
			nil,
		)
	}

	log.Printf("mdns: warning: no ULA/link-local IPv6 addresses found; advertising all addresses")
	return zeroconf.Register(
		name,
		serviceType,
		"local.",
		port,
		nil,
		nil,
	)
}

func (a *Advertiser) reannounceLoop(port int, name string, stopCh <-chan struct{}) {
	ticker := time.NewTicker(announceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			localAddrs := collectLocalIPv6Addrs()
			a.mu.Lock()
			if a.stopCh == nil {
				a.mu.Unlock()
				return
			}
			if a.server != nil {
				a.server.Shutdown()
				a.server = nil
			}
			a.mu.Unlock()

			server, err := publishService(port, name, localAddrs)
			if err != nil {
				log.Printf("mdns: re-announcement failed: %v", err)
				continue
			}
			a.mu.Lock()
			if a.stopCh == nil {
				a.mu.Unlock()
				server.Shutdown()
				return
			}
			a.server = server
			a.mu.Unlock()
			log.Printf("mdns: published %s \"%s\" on port %d", serviceType, name, port)
		case <-stopCh:
			return
		}
	}
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
	if a == nil {
		return
	}
	if port < 1 || port > 65535 {
		log.Printf("mdns: invalid port %d; refusing to advertise", port)
		return
	}

	localAddrs := collectLocalIPv6Addrs()
	server, err := publishService(port, name, localAddrs)
	if err != nil {
		log.Printf("mdns: failed to register: %v", err)
		return
	}

	a.mu.Lock()
	if a.stopCh != nil {
		close(a.stopCh)
		a.stopCh = nil
	}
	if a.server != nil {
		a.server.Shutdown()
		a.server = nil
	}
	a.server = server
	a.stopCh = make(chan struct{})
	stopCh := a.stopCh
	a.mu.Unlock()
	go a.reannounceLoop(port, name, stopCh)
	log.Printf("mdns: announced %s \"%s\" on port %d and will refresh every %s",
		serviceType, name, port, announceInterval)
}

// Stop unregisters the DNS-SD service.
func (a *Advertiser) Stop() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.stopCh != nil {
		close(a.stopCh)
		a.stopCh = nil
	}
	if a.server != nil {
		a.server.Shutdown()
		a.server = nil
	}
	a.mu.Unlock()
	log.Println("mdns: stopped")
}
