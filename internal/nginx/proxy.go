package nginx

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Reverse proxy is the ninth slice of M2. The operator supplies one upstream
// URL and whether WebSocket upgrades should be forwarded; the panel renders a
// fixed directive block around it. This is deliberately not a general "custom
// nginx snippet" feature: proxy_pass is the only operator value that reaches
// the config, and it is parsed into scheme/host/port/path before it is written.

const maxProxyTarget = 255

var (
	// A hostname label, not an IP literal. IPs (including IPv6) are checked with
	// net.ParseIP instead, because a colon inside brackets is not a label.
	proxyHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Proxy paths are restricted to characters that are inert in an nginx token.
	// In particular `$`, `;`, braces, quotes and whitespace are not accepted, so
	// the value cannot open a new directive or reference an nginx variable.
	proxyPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~%+:@/-]*$`)
)

// normalizeProxy trims and validates one upstream URL. It returns the canonical
// form that is written to the marker (lower-case scheme and host, no trailing
// slash rewriting) and the effective WebSocket flag.
//
// The empty target means "no proxy"; WebSocket without a target is refused
// because it has no meaning and would hide a form mistake.
func normalizeProxy(target string, websocket bool) (string, bool, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		if websocket {
			return "", false, fmt.Errorf("%w：启用 WebSocket 支持前必须先填写代理目标", ErrInvalid)
		}
		return "", false, nil
	}
	if len(target) > maxProxyTarget {
		return "", false, fmt.Errorf("%w：代理目标最多 %d 个字符", ErrInvalid, maxProxyTarget)
	}
	for _, r := range target {
		if r < 0x21 || r > 0x7e {
			return "", false, fmt.Errorf("%w：代理目标只能包含可打印 ASCII 字符（不能有空格、换行或中文）", ErrInvalid)
		}
	}
	if strings.ContainsAny(target, ";{}\"'\\$`") {
		return "", false, fmt.Errorf("%w：代理目标不能包含 ; { } 引号 反斜杠 $ 或反引号", ErrInvalid)
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", false, fmt.Errorf("%w：代理目标不是合法 URL：%v", ErrInvalid, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false, fmt.Errorf("%w：代理目标必须以 http:// 或 https:// 开头", ErrInvalid)
	}
	if u.Opaque != "" || u.Host == "" {
		return "", false, fmt.Errorf("%w：代理目标需要形如 http://127.0.0.1:3000", ErrInvalid)
	}
	if u.User != nil {
		return "", false, fmt.Errorf("%w：代理目标不能内嵌用户名或口令；凭据不应出现在站点配置里", ErrInvalid)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", false, fmt.Errorf("%w：代理目标不能带查询串或片段，只填写协议、主机与可选路径", ErrInvalid)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false, fmt.Errorf("%w：代理目标缺少主机名", ErrInvalid)
	}
	if ip := net.ParseIP(host); ip == nil {
		if len(host) > 253 {
			return "", false, fmt.Errorf("%w：代理目标主机名过长", ErrInvalid)
		}
		for _, label := range strings.Split(host, ".") {
			if !proxyHostRe.MatchString(label) {
				return "", false, fmt.Errorf("%w：代理目标主机名 %q 不合法", ErrInvalid, host)
			}
		}
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false, fmt.Errorf("%w：代理目标端口必须在 1-65535 之间", ErrInvalid)
		}
		port = strconv.Itoa(n)
	}
	hostPort := host
	if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	if port != "" {
		hostPort = net.JoinHostPort(host, port)
	}

	path := u.EscapedPath()
	if path != "" {
		// EscapedPath is what gets written; u.Path is decoded and catches
		// percent-encoded traversal (/%2e%2e/) that the literal check would miss.
		if !proxyPathRe.MatchString(path) || strings.Contains(path, "..") || strings.Contains(u.Path, "..") {
			return "", false, fmt.Errorf("%w：代理路径只能包含字母、数字与 . _ ~ %% + : @ / -，且不能有 ..", ErrInvalid)
		}
		for _, r := range u.Path {
			if r < 0x20 || r > 0x7e {
				return "", false, fmt.Errorf("%w：代理路径只能包含可打印 ASCII 字符", ErrInvalid)
			}
		}
	}
	return scheme + "://" + hostPort + path, websocket, nil
}

// proxyLocationBody renders the fixed directives for a proxied `location /`.
// Keeping this mapping in one function is what makes the validation above
// meaningful: only the normalised target can reach nginx, and every other line
// is a constant.
func proxyLocationBody(s Site) string {
	var b strings.Builder
	b.WriteString("        proxy_pass " + s.ProxyTarget + ";\n")
	b.WriteString("        proxy_http_version 1.1;\n")
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	if s.ProxyWebSocket {
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
	}
	return b.String()
}

// SetProxy enables, replaces or clears a site's upstream. Clearing is allowed
// even when the site is otherwise healthy: it is the rescue path back to a
// local static/PHP vhost. A non-empty target requires the rewrite template to
// be `none`, because both own `location /` and two owners would make the
// rendered config depend on line order.
func (m *Manager) SetProxy(name, target string, websocket bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	target, websocket, err := normalizeProxy(target, websocket)
	if err != nil {
		return Site{}, err
	}
	if target != "" && normalizeRewrite(site.Rewrite) != "none" {
		return Site{}, fmt.Errorf("%w：站点正在使用伪静态模板 %q，它和反向代理都写 location /；先把伪静态切回 none", ErrInvalid, site.Rewrite)
	}
	site.ProxyTarget, site.ProxyWebSocket = target, websocket
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
