package nginx

import (
	"fmt"
	"regexp"
	"strings"
)

// Per-path redirects are the fourteenth slice of M2. Site-wide redirect owns
// `location /`; this feature adds exact `location = /path` blocks that override
// the default handler for listed URIs only. Each rule is a path, one absolute
// http/https target and a 301/302 status; the query string is preserved by the
// constant `$is_args$args`, never by caller-supplied configuration text.

const maxRedirectPathRules = 10

var redirectPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,127}$`)

// RedirectRule is one exact path exception in a site-wide redirect table.
type RedirectRule struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	Code   int    `json:"code"`
}

// normalizeRedirectPaths validates and canonicalizes a whole table. An empty
// table is the clear operation. Paths become exact `location =` tokens, so they
// are validated by shape before anything reaches nginx.
func normalizeRedirectPaths(rules []RedirectRule) ([]RedirectRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if len(rules) > maxRedirectPathRules {
		return nil, fmt.Errorf("%w：按路径跳转最多 %d 条", ErrInvalid, maxRedirectPathRules)
	}
	seen := make(map[string]bool, len(rules))
	out := make([]RedirectRule, 0, len(rules))
	for i, rule := range rules {
		path := strings.TrimSpace(rule.Path)
		if path == "/" {
			return nil, fmt.Errorf("%w：按路径跳转不能用 /，它已经由整站跳转或 location / 接管", ErrInvalid)
		}
		if !redirectPathRe.MatchString(path) {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 只能包含字母、数字与 . _ ~ / -，且必须以 / 开头", ErrInvalid, i+1, rule.Path)
		}
		if strings.Contains(path, "..") {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 不能包含 ..", ErrInvalid, i+1, path)
		}
		path = strings.TrimRight(path, "/")
		if path == "/" || path == "" {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 去掉尾部斜杠后变成站点根路径", ErrInvalid, i+1, rule.Path)
		}
		if strings.HasPrefix(path, "/.well-known/acme-challenge") {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 会遮蔽 ACME HTTP-01 校验路径", ErrInvalid, i+1, path)
		}
		if seen[path] {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 重复", ErrInvalid, i+1, path)
		}
		seen[path] = true

		code := rule.Code
		if code != redirectMovedPermanently && code != redirectFound {
			return nil, fmt.Errorf("%w：第 %d 条跳转状态码只能是 301 或 302", ErrInvalid, i+1)
		}
		u, err := parseUpstreamURL(strings.TrimSpace(rule.Target), "跳转目标")
		if err != nil {
			return nil, fmt.Errorf("%w：第 %d 条%s", ErrInvalid, i+1, err)
		}
		out = append(out, RedirectRule{Path: path, Target: u.String(), Code: code})
	}
	return out, nil
}

// redirectPathLocations renders fixed exact locations before `location /`.
// nginx evaluates exact locations before prefixes, so these rules are path
// exceptions for site-wide static, proxy or redirect behavior. Query strings
// are preserved by a constant; no rule can introduce a new directive.
func redirectPathLocations(rules []RedirectRule) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString("    location = " + r.Path + " {\n")
		b.WriteString(fmt.Sprintf("        return %d %s$is_args$args;\n", r.Code, r.Target))
		b.WriteString("    }\n")
	}
	return b.String()
}

// SetRedirectPaths replaces or clears the per-path redirect table. Clearing is
// always allowed. Exact locations do not own `location /`, so this table can
// coexist with pseudo-static templates, reverse proxy, site-wide redirect,
// hotlink protection, Basic Auth, real IP resolution and PHP binding.
func (m *Manager) SetRedirectPaths(name string, rules []RedirectRule) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	rules, err := normalizeRedirectPaths(rules)
	if err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if err := errorPagesCollide(site.ErrorPages, rules); err != nil {
		return Site{}, err
	}
	site.RedirectPaths = rules
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
