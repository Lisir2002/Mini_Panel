package sec

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ValidateIPAllowlist checks the textual form stored in panel.ip_allowlist:
// newline-separated entries, each a bare address or a CIDR, with blank lines and
// "#" comments allowed.
//
// Hostnames are rejected on purpose. Resolving a name means the allow decision
// depends on a DNS server the panel does not control, and anyone who can poison
// that record walks straight through the list — so the list is only a list while
// every entry is a literal address.
//
// It lives here rather than in internal/api because the CLI has to accept the
// same format (minipanel reset-ips --set), and a second copy of these rules is
// how a value the API accepts ends up being one the middleware reads differently.
func ValidateIPAllowlist(raw string) error {
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if _, _, err := net.ParseCIDR(line); err != nil {
				return fmt.Errorf("非法 CIDR（第 %d 行）：%s", i+1, line)
			}
			continue
		}
		if net.ParseIP(line) == nil {
			return fmt.Errorf("非法 IP（第 %d 行，仅支持 IP 与 CIDR，不支持域名）：%s", i+1, line)
		}
	}
	return nil
}

// NormalizeIPAllowlist trims each entry and drops empty lines, keeping comments,
// so what reset-ips writes is exactly what the middleware will read. An empty
// result means "no restriction", which is the documented meaning of a blank list.
func NormalizeIPAllowlist(raw string) (string, error) {
	if err := ValidateIPAllowlist(raw); err != nil {
		return "", err
	}
	var kept []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		return "", nil
	}
	out := strings.Join(kept, "\n")
	if !strings.Contains(out, "\n") && strings.HasPrefix(out, "#") {
		// A single comment line is not a policy: it reads as "no restriction"
		// anyway, so refuse instead of leaving the operator believing otherwise.
		return "", errors.New("白名单里只有注释，等同不限制；请给出地址/CIDR，或用 --clear 明确清空")
	}
	return out + "\n", nil
}
