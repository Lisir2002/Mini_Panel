package api

import "net"

// isLoopback reports whether s is a loopback address or the localhost name.
//
// It guards the one exception to "never send credentials over plain HTTP": a
// panel bound to loopback, talked to from loopback, is not exposed to anybody
// else. Anything else has to have TLS.
//
// The allowlist format lives with the rest of the input rules in internal/sec,
// because the CLI has to accept exactly what this package will enforce.
func isLoopback(s string) bool {
	if s == "localhost" {
		return true
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}
