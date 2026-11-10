package sec

import (
	"sync"
	"time"
)

// Limiter is the per-IP login failure gate, keyed on IP *and* username: five
// failures then a doubling lockout with a countdown, capped at an hour.
//
// The counters live in memory only, and that is a real trade-off, not a
// benefit: restarting the panel does clear an in-flight lockout. It is
// acceptable because the lockout's job is to slow a live brute-force attempt,
// not to punish after the fact, and because the durable record — every failed
// attempt with its IP and result — is written to SQLite and survives restarts.
// Persisting counters would also mean a stale lockout keeps a legitimate
// operator out across an unrelated maintenance reboot.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxLock time.Duration
	cells   map[string]*cell
}

type cell struct {
	fails int
	until time.Time
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	if limit <= 0 {
		limit = 5
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		maxLock: time.Hour,
		cells:   map[string]*cell{},
	}
}

// Blocked reports whether an attempt may proceed, and for how long to wait.
func (l *Limiter) Blocked(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.cells[key]
	if c == nil {
		return false, 0
	}
	if c.until.After(now) {
		return true, c.until.Sub(now)
	}
	if !c.until.IsZero() && now.After(c.until) && c.fails >= l.limit {
		// Lockout expired: give one more chance and decay the counter.
		c.fails = l.limit - 1
		c.until = time.Time{}
	}
	return false, 0
}

func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.cells[key]
	if c == nil {
		c = &cell{}
		l.cells[key] = c
	}
	c.fails++
	if c.fails >= l.limit {
		over := c.fails - l.limit
		d := l.window << over
		if over > 6 || d > l.maxLock || d <= 0 {
			d = l.maxLock
		}
		c.until = now.Add(d)
	}
}

func (l *Limiter) Pass(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.cells, key)
}

// Snapshot is exposed on the security page so an operator can see who is
// currently locked out without grepping logs.
func (l *Limiter) Snapshot(now time.Time) map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]int64{}
	for k, c := range l.cells {
		if c.until.After(now) {
			out[k] = int64(c.until.Sub(now).Seconds())
		}
	}
	return out
}
