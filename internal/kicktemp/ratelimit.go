package kicktemp

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrRateLimited is returned when a GTM request would have to wait longer than
// KT_GTM_MAX_WAIT for a free slot.
var ErrRateLimited = errors.New("rate limited, retry later")

const rateWindow = time.Minute

// Limiter caps outgoing GTM API requests process-wide at qpm per minute.
//
// It is a sliding window, not a plain token bucket: a bucket with burst = qpm
// can send up to 2*qpm requests within one minute (a full burst plus a full
// refill), which would exceed the API quota of 30/minute. Here no window of
// one minute ever contains more than qpm requests.
type Limiter struct {
	qpm     int
	maxWait time.Duration
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error

	mu    sync.Mutex
	slots []time.Time // scheduled send times, ascending
}

// NewLimiter creates a limiter with the real clock.
func NewLimiter(qpm int, maxWait time.Duration) *Limiter {
	return &Limiter{qpm: qpm, maxWait: maxWait, now: time.Now, sleep: sleepCtx}
}

// NewLimiterWithClock is NewLimiter with an injectable clock (tests).
func NewLimiterWithClock(qpm int, maxWait time.Duration, now func() time.Time, sleep func(context.Context, time.Duration) error) *Limiter {
	return &Limiter{qpm: qpm, maxWait: maxWait, now: now, sleep: sleep}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait blocks until a request may be sent. It fails with ErrRateLimited without
// consuming a slot when the wait would exceed maxWait.
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := l.now()
	// Drop slots that left the window.
	i := 0
	for i < len(l.slots) && !l.slots[i].After(now.Add(-rateWindow)) {
		i++
	}
	l.slots = l.slots[i:]

	at := now
	if n := len(l.slots); n >= l.qpm {
		if t := l.slots[n-l.qpm].Add(rateWindow); t.After(at) {
			at = t
		}
	}
	if n := len(l.slots); n > 0 && l.slots[n-1].After(at) {
		at = l.slots[n-1]
	}
	wait := at.Sub(now)
	if wait > l.maxWait {
		l.mu.Unlock()
		return ErrRateLimited
	}
	l.slots = append(l.slots, at)
	l.mu.Unlock()
	return l.sleep(ctx, wait)
}

// Wrap returns a RoundTripper that waits for a slot before every request and
// counts it on the request's call counter. It belongs outside the OAuth
// transport, so token refreshes are not counted against the GTM quota.
func (l *Limiter) Wrap(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := l.Wait(req.Context()); err != nil {
			return nil, err
		}
		if c := callCounterFrom(req.Context()); c != nil {
			c.Add(1)
		}
		return next.RoundTrip(req)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type counterKey struct{}

// withCallCounter returns a context whose GTM requests are counted.
func withCallCounter(ctx context.Context) (context.Context, *atomic.Int64) {
	c := new(atomic.Int64)
	return context.WithValue(ctx, counterKey{}, c), c
}

func callCounterFrom(ctx context.Context) *atomic.Int64 {
	c, _ := ctx.Value(counterKey{}).(*atomic.Int64)
	return c
}
