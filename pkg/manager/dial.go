package manager

import (
	"context"
	"log"
	"net"
	"time"
)

// dialWithTimeout abstracts common logic for Dial and DialTimeout across tunnel managers.
func DialWithTimeout(
	debug bool,
	setup func() error,
	dial func(ctx context.Context, network, address string) (net.Conn, error),
	addr, port string,
	timeout time.Duration,
	label string,
) (net.Conn, error) {
	if setup != nil {
		if err := setup(); err != nil {
			return nil, err
		}
	}
	if debug {
		log.Printf("Dialing over %s tunnel...", label)
	}
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return dial(ctx, "tcp", net.JoinHostPort(addr, port))
}
