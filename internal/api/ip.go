package api

import "net"

// isIP reports whether s is a bare IP address.
//
// The panel IP allowlist accepts addresses and CIDRs only. Hostnames are
// deliberately rejected: resolving one means the allow decision depends on a
// DNS server the panel does not control, and an attacker who can poison that
// record walks straight through the list.
func isIP(s string) bool { return net.ParseIP(s) != nil }

// isCIDR reports whether s is a valid network in prefix form.
func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// isLoopback reports whether s is a loopback address or the localhost name.
func isLoopback(s string) bool {
	if s == "localhost" {
		return true
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}
