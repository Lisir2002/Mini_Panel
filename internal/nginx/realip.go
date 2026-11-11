package nginx

import (
	"fmt"
	"net"
	"strings"
)

// Real IP resolution is the thirteenth slice of M2. A site behind a CDN or a
// reverse proxy sees the proxy's address as $remote_addr; nginx can replace it
// with the address named by a forwarding header, but only for peers the
// operator explicitly trusts. Trust is therefore a list of addresses/CIDRs that
// the caller must supply: there is no "trust everything" switch, because a
// single untrusted client could then forge its own address in the site log (and,
// once per-site allow/deny rules exist, in those too).

const (
	realIPHeaderXFF   = "X-Forwarded-For"
	realIPHeaderXReal = "X-Real-IP"
	// maxRealIPSources bounds the marker and the config block. A real deployment
	// needs its CDN's ranges, not an unbounded pastebin.
	maxRealIPSources = 16
)

// normalizeRealIP validates the trust list and header, and returns the canonical
// form stored in the marker. An empty list with an empty header is the clear
// operation. A header without any trusted source is rejected: nginx would
// otherwise accept the header from every peer.
func normalizeRealIP(from []string, header string) ([]string, string, error) {
	header = strings.TrimSpace(header)
	if len(from) == 0 {
		if header != "" {
			return nil, "", fmt.Errorf("%w：启用真实 IP 解析至少要给出一个可信代理地址或网段", ErrInvalid)
		}
		return nil, "", nil
	}
	switch {
	case header == "":
		header = realIPHeaderXFF
	case strings.EqualFold(header, realIPHeaderXFF):
		header = realIPHeaderXFF
	case strings.EqualFold(header, realIPHeaderXReal):
		header = realIPHeaderXReal
	default:
		return nil, "", fmt.Errorf("%w：只支持 X-Forwarded-For 或 X-Real-IP，不接受其它请求头", ErrInvalid)
	}
	if len(from) > maxRealIPSources {
		return nil, "", fmt.Errorf("%w：可信代理最多 %d 条", ErrInvalid, maxRealIPSources)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(from))
	for _, raw := range from {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, "", fmt.Errorf("%w：可信代理列表里不能有空项", ErrInvalid)
		}
		entry, err := canonicalRealIPSource(raw)
		if err != nil {
			return nil, "", err
		}
		if seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("%w：可信代理列表里没有有效条目", ErrInvalid)
	}
	return out, header, nil
}

// canonicalRealIPSource accepts a bare IP or a CIDR. The returned string is what
// nginx receives, so the marker and the vhost cannot disagree about the shape.
func canonicalRealIPSource(raw string) (string, error) {
	if _, network, err := net.ParseCIDR(raw); err == nil {
		if ones, _ := network.Mask.Size(); ones == 0 {
			return "", fmt.Errorf("%w：不能信任 0.0.0.0/0 或 ::/0，那等于允许任何客户端伪造来源地址", ErrInvalid)
		}
		if network.IP.IsUnspecified() {
			return "", fmt.Errorf("%w：%s 不是可用的代理地址", ErrInvalid, raw)
		}
		return network.String(), nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("%w：%s 不是 IP 或 CIDR", ErrInvalid, raw)
	}
	if ip.IsUnspecified() {
		return "", fmt.Errorf("%w：%s 不是可用的代理地址", ErrInvalid, raw)
	}
	return ip.String(), nil
}

// realIPLines renders the three fixed directives. real_ip_recursive is only
// meaningful for X-Forwarded-For (nginx ignores it for X-Real-IP), so it is
// written only for the header that has a chain to walk.
func realIPLines(s Site) string {
	var b strings.Builder
	for _, from := range s.RealIPFrom {
		b.WriteString("    set_real_ip_from " + from + ";\n")
	}
	b.WriteString("    real_ip_header " + s.RealIPHeader + ";\n")
	if s.RealIPHeader == realIPHeaderXFF {
		b.WriteString("    real_ip_recursive on;\n")
	}
	return b.String()
}

// SetRealIP replaces or clears the trusted-proxy configuration. Clearing (empty
// from list and empty header) is always allowed. It is a server-level directive:
// it does not own `location /`, so it coexists with every other site feature.
func (m *Manager) SetRealIP(name string, from []string, header string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	from, header, err := normalizeRealIP(from, header)
	if err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	site.RealIPFrom = from
	site.RealIPHeader = header
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
