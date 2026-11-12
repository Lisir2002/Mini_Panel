package nginx

import (
	"fmt"
	"strings"
)

// Site-wide redirect is the tenth slice of M2. The operator supplies one
// absolute http/https URL, a 301/302 status and whether the original path
// should be preserved. Like reverse proxy, the value is parsed into
// scheme/host/port/path before it reaches nginx; the `return` line is fixed.

const (
	redirectMovedPermanently = 301
	redirectFound            = 302
)

// normalizeRedirect validates one redirect target. An empty target clears the
// redirect regardless of the other fields, so the UI can always send a rescue
// request. keepPath trims trailing slashes from the target path because
// $request_uri starts with one; the rendered line then appends the original
// request URI.
func normalizeRedirect(target string, code int, keepPath bool) (string, int, bool, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, false, nil
	}
	if code != redirectMovedPermanently && code != redirectFound {
		return "", 0, false, fmt.Errorf("%w：跳转状态码只能是 301 或 302", ErrInvalid)
	}
	u, err := parseUpstreamURL(target, "跳转目标")
	if err != nil {
		return "", 0, false, err
	}
	path := u.path
	if keepPath {
		path = strings.TrimRight(path, "/")
	}
	return u.withPath(path), code, keepPath, nil
}

// redirectLocationBody renders the fixed `return` line for a redirecting site.
// KeepPath appends nginx's original request URI, so /old/path becomes
// https://new.example.com/old/path without the panel interpolating anything.
func redirectLocationBody(s Site) string {
	target := s.RedirectTarget
	if s.RedirectKeepPath {
		target += "$request_uri"
	}
	return fmt.Sprintf("        return %d %s;\n", s.RedirectCode, target)
}

// SetRedirect enables, replaces or clears a site-wide redirect. Clearing is
// always allowed. A non-empty target requires both the rewrite template and the
// reverse proxy to be empty because all three write `location /`.
func (m *Manager) SetRedirect(name, target string, code int, keepPath bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	target, code, keepPath, err := normalizeRedirect(target, code, keepPath)
	if err != nil {
		return Site{}, err
	}
	if target != "" {
		if normalizeRewrite(site.Rewrite) != "none" {
			return Site{}, fmt.Errorf("%w：站点正在使用伪静态模板 %q，它和整站跳转都写 location /；先把伪静态切回 none", ErrInvalid, site.Rewrite)
		}
		if site.proxyActive() {
			return Site{}, fmt.Errorf("%w：站点正在使用反向代理，location / 已由代理接管；先清除代理再启用整站跳转", ErrInvalid)
		}
		if site.Hotlink {
			return Site{}, fmt.Errorf("%w：站点已启用防盗链，静态资源由本机处理；先关闭防盗链再启用整站跳转", ErrInvalid)
		}
	}
	site.RedirectTarget, site.RedirectCode, site.RedirectKeepPath = target, code, keepPath
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
