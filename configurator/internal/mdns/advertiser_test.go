package mdns

import (
	"testing"
	"time"
)

func TestAdvertiserStartStop(t *testing.T) {
	a := &Advertiser{}
	a.Start(9000, "Viking Bio Configurator")
	time.Sleep(50 * time.Millisecond)
	a.Stop()
}

func TestAdvertiserRejectsInvalidPort(t *testing.T) {
	a := &Advertiser{}
	a.Start(0, "Viking Bio Configurator")
	if a.server != nil {
		t.Fatal("expected invalid-port start to leave the server unset")
	}
	if a.stopCh != nil {
		t.Fatal("expected invalid-port start to leave the stop channel unset")
	}
}
