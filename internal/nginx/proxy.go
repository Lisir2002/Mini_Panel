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

const maxUpstreamTarget = 255

var (
	// A hostname label, not an IP literal. IPs (including IPv6) are checked with
	// net.ParseIP instead, because a colon inside brackets is not a label.
	upstreamHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// Upstream paths are restricted to characters that are inert in an nginx
	// token. In particular `$`, `;`, braces, quotes and whitespace are not
	// accepted, so the value cannot open a new directive or reference an nginx
	// variable.
	upstreamPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~%+:@/-]*$`)
)

// upstreamURL is the validated, canonical form of a URL that may reach an nginx
// directive: scheme and host are lower-cased, the port is normalised, and the
// path is percent-encoded exactly as it will be written. Nothing outside these
// three fields can be supplied by a request.
type upstreamURL struct {
	scheme   string
	hostPort string
	path     string
}

func (u upstreamURL) String() string {
	return u.scheme + "://" + u.hostPort + u.path
}

func (u upstreamURL) withPath(path string) string {
	return u.scheme + "://" + u.hostPort + path
}

// parseUpstreamURL validates one operator-supplied URL. `what` names the field
// in error messages ("代理目标" or "跳转目标"). Only http/https, a DNS hostname
// or IP literal, a 1-65535 port and a restricted path are accepted; userinfo,
// query strings, fragments, control characters and nginx metacharacters are
// refused.
func parseUpstreamURL(raw, what string) (upstreamURL, error) {
	if len(raw) > maxUpstreamTarget {
		return upstreamURL{}, fmt.Errorf("%w：%s最多 %d 个字符", ErrInvalid, what, maxUpstreamTarget)
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return upstreamURL{}, fmt.Errorf("%w：%s只能包含可打印 ASCII 字符（不能有空格、换行或中文）", ErrInvalid, what)
		}
	}
	if strings.ContainsAny(raw, ";{}\"'\\$`") {
		return upstreamURL{}, fmt.Errorf("%w：%s不能包含 ; { } 引号 反斜杠 $ 或反引号", ErrInvalid, what)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return upstreamURL{}, fmt.Errorf("%w：%s不是合法 URL：%v", ErrInvalid, what, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return upstreamURL{}, fmt.Errorf("%w：%s必须以 http:// 或 https:// 开头", ErrInvalid, what)
	}
	if u.Opaque != "" || u.Host == "" {
		return upstreamURL{}, fmt.Errorf("%w：%s需要形如 http://127.0.0.1:3000", ErrInvalid, what)
	}
	if u.User != nil {
		return upstreamURL{}, fmt.Errorf("%w：%s不能内嵌用户名或口令；凭据不应出现在站点配置里", ErrInvalid, what)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return upstreamURL{}, fmt.Errorf("%w：%s不能带查询串或片段，只填写协议、主机与可选路径", ErrInvalid, what)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return upstreamURL{}, fmt.Errorf("%w：%s缺少主机名", ErrInvalid, what)
	}
	if ip := net.ParseIP(host); ip == nil {
		if len(host) > 253 {
			return upstreamURL{}, fmt.Errorf("%w：%s主机名过长", ErrInvalid, what)
		}
		for _, label := range strings.Split(host, ".") {
			if !upstreamHostRe.MatchString(label) {
				return upstreamURL{}, fmt.Errorf("%w：%s主机名 %q 不合法", ErrInvalid, what, host)
			}
		}
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return upstreamURL{}, fmt.Errorf("%w：%s端口必须在 1-65535 之间", ErrInvalid, what)
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
		if !upstreamPathRe.MatchString(path) || strings.Contains(path, "..") || strings.Contains(u.Path, "..") {
			return upstreamURL{}, fmt.Errorf("%w：%s路径只能包含字母、数字与 . _ ~ %% + : @ / -，且不能有 ..", ErrInvalid, what)
		}
		for _, r := range u.Path {
			if r < 0x20 || r > 0x7e {
				return upstreamURL{}, fmt.Errorf("%w：%s路径只能包含可打印 ASCII 字符", ErrInvalid, what)
			}
		}
	}
	return upstreamURL{scheme: scheme, hostPort: hostPort, path: path}, nil
}

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
	u, err := parseUpstreamURL(target, "代理目标")
	if err != nil {
		return "", false, err
	}
	return u.String(), websocket, nil
}

// proxyLocationBody renders the fixed directives for a proxied `location /`.
// Keeping this mapping in one function is what makes the validation above
// meaningful: only the normalised target can reach nginx, and every other line
// is a constant.
func proxyLocationBody(s Site) string {
	var b strings.Builder
	if len(s.ProxyUpstreams) > 0 {
		// The balancing table owns location / through a panel-defined
		// upstream name; the servers themselves live in the http-level table
		// file written in the same transaction.
		b.WriteString("        proxy_pass http://" + upstreamName(s.Name) + ";\n")
	} else {
		b.WriteString("        proxy_pass " + s.ProxyTarget + ";\n")
	}
	b.WriteString("        proxy_http_version 1.1;\n")
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	if s.ProxyWebSocket {
		b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("        proxy_set_header Connection \"upgrade\";\n")
	}
	if s.ProxyCache != nil {
		b.WriteString(proxyCacheLines(s))
	}
	return b.String()
}

// SetProxy enables, replaces or clears a site's upstream. Clearing is allowed
// even when the site is otherwise healthy: it is the rescue path back to a
// local static/PHP vhost. A non-empty target requires the rewrite template to
// be `none` and no site-wide redirect, because all three own `location /` and
// two owners would make the rendered config depend on line order.
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
	if target != "" {
		if normalizeRewrite(site.Rewrite) != "none" {
			return Site{}, fmt.Errorf("%w：站点正在使用伪静态模板 %q，它和反向代理都写 location /；先把伪静态切回 none", ErrInvalid, site.Rewrite)
		}
		if site.RedirectTarget != "" {
			return Site{}, fmt.Errorf("%w：站点正在整站跳转，location / 已由跳转规则接管；先清除跳转再启用反向代理", ErrInvalid)
		}
		if site.Hotlink {
			return Site{}, fmt.Errorf("%w：站点已启用防盗链，静态资源由本机处理；先关闭防盗链再启用反向代理", ErrInvalid)
		}
	}
	// Setting a single target replaces any balancing table: both forms own
	// location /, so the upstream table has to be rebuilt in the same
	// transaction, exactly like SetProxyUpstreams does in reverse.
	rows, err := m.upstreamRows(name, nil, "")
	if err != nil {
		return Site{}, err
	}
	site.ProxyTarget, site.ProxyWebSocket = target, websocket
	site.ProxyUpstreams, site.ProxyLBMethod = nil, ""
	if target == "" && site.ProxyCache != nil {
		// Clearing the last proxy owner drops the cache with it: the policy
		// only means something beside a proxy_pass, and the zone table has to
		// lose the row in the same transaction.
		site.ProxyCache = nil
	}
	body := render(site)
	files := []configFile{{Path: site.ConfigPath, Body: &body}}
	if len(rows) > 0 || m.upstreamsFileExists() {
		tablePath, err := m.upstreamsPath()
		if err != nil {
			return Site{}, err
		}
		table := renderUpstreams(rows)
		files = append(files, configFile{Path: tablePath, Body: &table, OwnedCheck: parseUpstreamsMarker})
	}
	cacheRows, err := m.cacheRows(name, site.ProxyCache)
	if err != nil {
		return Site{}, err
	}
	files, err = m.cacheTableFile(cacheRows, files)
	if err != nil {
		return Site{}, err
	}
	if err := m.applyFiles(files); err != nil {
		return Site{}, err
	}
	if target == "" {
		m.removeCacheDir(name)
	}
	return site, nil
}
