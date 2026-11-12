package nginx

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Custom error pages are the nineteenth slice of M2. Each rule maps one HTTP
// error status to a URI inside the site's own document root; nginx renders it
// as a server-level `error_page <code> <path>;` line plus one exact static
// location for the page path, so the internal redirect is served from the
// site root even when `location /` proxies or redirects. The table does not
// own `location /`, so it coexists with rewrite templates, reverse proxy,
// site-wide redirect, per-path redirects, hotlink protection, Basic Auth,
// autoindex and PHP binding; a page path may not collide with a per-path
// redirect exception (both would render the same `location =` token).

const maxErrorPageRules = 10

var errorPagePathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,127}$`)

// errorPageCodes is the closed status vocabulary. Only statuses nginx can
// actually replace via error_page are accepted; a code outside this list is a
// validation error, never a silently dropped rule.
var errorPageCodes = map[int]bool{
	400: true, 401: true, 403: true, 404: true, 405: true,
	408: true, 500: true, 502: true, 503: true, 504: true,
}

// ErrorPageRule maps one error status to a URI under the site root.
type ErrorPageRule struct {
	Code int    `json:"code"`
	Path string `json:"path"`
}

// normalizeErrorPages validates and canonicalizes a whole table. An empty
// table is the clear operation. Paths become tokens in an nginx directive, so
// they are validated by shape before anything reaches the config file.
func normalizeErrorPages(rules []ErrorPageRule) ([]ErrorPageRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if len(rules) > maxErrorPageRules {
		return nil, fmt.Errorf("%w：自定义错误页最多 %d 条", ErrInvalid, maxErrorPageRules)
	}
	seen := make(map[int]bool, len(rules))
	out := make([]ErrorPageRule, 0, len(rules))
	for i, rule := range rules {
		if !errorPageCodes[rule.Code] {
			return nil, fmt.Errorf("%w：第 %d 条状态码 %d 不在支持列表（400/401/403/404/405/408/500/502/503/504）", ErrInvalid, i+1, rule.Code)
		}
		if seen[rule.Code] {
			return nil, fmt.Errorf("%w：第 %d 条状态码 %d 重复", ErrInvalid, i+1, rule.Code)
		}
		seen[rule.Code] = true
		path := strings.TrimSpace(rule.Path)
		if !errorPagePathRe.MatchString(path) {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 只能包含字母、数字与 . _ ~ / -，且必须以 / 开头", ErrInvalid, i+1, rule.Path)
		}
		if strings.Contains(path, "..") {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 不能包含 ..", ErrInvalid, i+1, path)
		}
		if strings.HasPrefix(path, "/.well-known/acme-challenge") {
			return nil, fmt.Errorf("%w：第 %d 条路径 %q 会遮蔽 ACME HTTP-01 校验路径", ErrInvalid, i+1, path)
		}
		out = append(out, ErrorPageRule{Code: rule.Code, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out, nil
}

// errorPageLines renders fixed server-level error_page directives. Each path
// is an internal URI nginx resolves against the site root; no rule can
// introduce a new directive or escape the vhost.
func errorPageLines(rules []ErrorPageRule) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(fmt.Sprintf("    error_page %d %s;\n", r.Code, r.Path))
	}
	return b.String()
}

// errorPageLocations renders one exact static location per distinct page
// path. Without it the error_page internal redirect would land in whatever
// owns `location /` — on a proxy site the error page itself would be fetched
// from the (possibly dead) upstream, which is exactly the moment the page is
// needed. The empty block inherits the server root and serves the file
// statically; a missing file falls back to nginx's built-in error response.
func errorPageLocations(rules []ErrorPageRule) string {
	var b strings.Builder
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.Path] {
			continue
		}
		seen[r.Path] = true
		b.WriteString("    location = " + r.Path + " {\n")
		b.WriteString("        # minipanel error page: always served from the site root\n")
		b.WriteString("    }\n")
	}
	return b.String()
}

// errorPagesCollide reports whether an error page path duplicates a per-path
// redirect exception. Both render `location = <path>`, and nginx refuses a
// duplicate exact location, so the collision is rejected with a reason here
// instead of surfacing as an opaque nginx -t failure.
func errorPagesCollide(pages []ErrorPageRule, paths []RedirectRule) error {
	for _, p := range pages {
		for _, r := range paths {
			if p.Path == r.Path {
				return fmt.Errorf("%w：错误页路径 %q 与按路径跳转的同名例外冲突，请先改掉其中一边", ErrInvalid, p.Path)
			}
		}
	}
	return nil
}

// SetErrorPages replaces or clears the custom error page table. Clearing is
// always allowed. The error_page directives do not own `location /`, so the
// table coexists with every other site feature. For proxied sites the lines
// only affect errors nginx itself generates; upstream error responses pass
// through unchanged (the panel never enables proxy_intercept_errors).
func (m *Manager) SetErrorPages(name string, rules []ErrorPageRule) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	rules, err := normalizeErrorPages(rules)
	if err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if err := errorPagesCollide(rules, site.RedirectPaths); err != nil {
		return Site{}, err
	}
	site.ErrorPages = rules
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
