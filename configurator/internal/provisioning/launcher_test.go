package provisioning

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForConnectionRetriesUntilAvailable(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	connected := make(chan struct{}, 1)

	waitForConnection(func() error {
		if attempts.Add(1) < 3 {
			return errors.New("not ready")
		}
		connected <- struct{}{}
		return nil
	}, "/dev/ttyACM0", 0, func() {})

	select {
	case <-connected:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected connection retry to succeed")
	}
}
