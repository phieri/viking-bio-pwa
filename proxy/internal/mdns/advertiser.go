package mdns

import (
	"log"

	"github.com/grandcat/zeroconf"
)

const serviceType = "_viking-bio._tcp"

// Advertiser publishes the proxy as a DNS-SD service.
type Advertiser struct {
	server *zeroconf.Server
}

// Start registers the DNS-SD service record on the given port with the given name.
func (a *Advertiser) Start(port int, name string) {
	var err error
	a.server, err = zeroconf.Register(
		name,
		serviceType,
		"local.",
		port,
		[]string{"path=/api/data"},
		nil,
	)
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
