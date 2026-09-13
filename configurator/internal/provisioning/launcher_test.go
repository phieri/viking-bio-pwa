package provisioning

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForConnectionRetriesUntilAvailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var attempts atomic.Int32
	connected := make(chan struct{}, 1)

	waitForConnection(ctx, func() error {
		if attempts.Add(1) < 3 {
			return errors.New("not ready")
		}
		connected <- struct{}{}
		return nil
	}, "/dev/ttyACM0", 0, func() {})

	select {
	case <-connected:
		cancel()
	case <-time.After(500 * time.Millisecond):
		cancel()
		t.Fatal("expected connection retry to succeed")
	}
}
