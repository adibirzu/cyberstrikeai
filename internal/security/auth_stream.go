package security

import (
	"context"
	"time"
)

type sessionLeaseKey struct{}
type sessionLease struct {
	expiresAt time.Time
	valid     func() bool
}

func withSessionLease(ctx context.Context, expiry time.Time, valid func() bool) context.Context {
	return context.WithValue(ctx, sessionLeaseKey{}, sessionLease{expiry, valid})
}

// AuthenticatedStreamContext caps a connection at the immutable native/identity
// expiry, and cancels revoked/disabled sessions within one second even when idle.
// Client traffic and pongs never extend this deadline. Missing auth fails closed.
func AuthenticatedStreamContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	lease, ok := parent.Value(sessionLeaseKey{}).(sessionLease)
	deadline := lease.expiresAt
	if maximum > 0 {
		cap := time.Now().Add(maximum)
		if deadline.IsZero() || cap.Before(deadline) {
			deadline = cap
		}
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	if !ok || lease.valid == nil || !lease.valid() {
		cancel()
		return ctx, cancel
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !lease.valid() {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

// AuthenticatedSessionValid rechecks authority before consequential stream input
// or delivery, rather than waiting for the idle-connection cancellation tick.
func AuthenticatedSessionValid(ctx context.Context) bool {
	lease, ok := ctx.Value(sessionLeaseKey{}).(sessionLease)
	return ok && ctx.Err() == nil && time.Now().Before(lease.expiresAt) && lease.valid != nil && lease.valid()
}
