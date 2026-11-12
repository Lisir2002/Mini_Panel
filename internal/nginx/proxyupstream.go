package nginx

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Multi-upstream reverse proxy (load balancing) is the twentieth slice of M2.
// The operator supplies a table of upstream servers plus one balancing method;
// the panel renders a panel-owned http-level `upstream` table and points the
// site's `location /` at it with a fixed proxy_pass. Like the traffic-limit
// zones, `upstream` blocks must live outside any server block, so the table is
// written into a directory the host's own nginx.conf provably includes at http
// level, in the same test-before-reload transaction as the vhost.

const (
	maxProxyUpstreams = 10
	maxUpstreamWeight = 100
	// upstreamsFileName follows the zone table's naming rule: one dot, before
	// the conf suffix, so the host's `*` and `*.conf` globs cannot pick the
	// file up under two different names.
	upstreamsFileName   = filePrefix + "upstreams." + limitsFileSuffix
	upstreamsMarkerLine = "# minipanel-upstreams: "
)

// ProxyUpstream is one backend server in a site's balancing table. Target is
// the canonical http://host:port form; Weight is nginx's relative weight
// (1-100, 1 being the default and omitted from the rendered line).
type ProxyUpstream struct {
	Target string `json:"target"`
	Weight int    `json:"weight,omitempty"`
}

// proxyLBMethods is the closed balancing vocabulary. The empty method is
// nginx's default weighted round-robin and renders no directive; "round_robin"
// is accepted as an explicit spelling of the same default and normalized away.
var proxyLBMethods = map[string]bool{
	"":           true,
	"ip_hash":    true,
	"least_conn": true,
}

// normalizeProxyLBMethod validates and canonicalizes the balancing method.
func normalizeProxyLBMethod(method string) (string, error) {
	method = strings.TrimSpace(method)
	if method == "round_robin" {
		method = ""
	}
	if !proxyLBMethods[method] {
		return "", fmt.Errorf("%w：负载均衡算法只支持 round_robin（默认）、ip_hash 与 least_conn", ErrInvalid)
	}
	return method, nil
}

// normalizeProxyUpstreams validates and canonicalizes a whole upstream table.
// An empty table is the clear operation. Targets reuse parseUpstreamURL but
// are further restricted to plain http with no path: nginx's `server` directive
// takes host:port only (no scheme, no URI), and TLS-to-upstream is a separate
// feature this slice deliberately does not offer.
func normalizeProxyUpstreams(ups []ProxyUpstream) ([]ProxyUpstream, error) {
	if len(ups) == 0 {
		return nil, nil
	}
	if len(ups) > maxProxyUpstreams {
		return nil, fmt.Errorf("%w：上游服务器最多 %d 台", ErrInvalid, maxProxyUpstreams)
	}
	seen := make(map[string]bool, len(ups))
	out := make([]ProxyUpstream, 0, len(ups))
	for i, up := range ups {
		u, err := parseUpstreamURL(strings.TrimSpace(up.Target), "上游地址")
		if err != nil {
			return nil, fmt.Errorf("%w：第 %d 台%s", ErrInvalid, i+1, err)
		}
		if u.scheme != "http" {
			return nil, fmt.Errorf("%w：第 %d 台上游只支持 http://（nginx 的 upstream server 不带协议，回源 HTTPS 不在本片范围）", ErrInvalid, i+1)
		}
		if u.path != "" {
			return nil, fmt.Errorf("%w：第 %d 台上游不能带路径，只填 http://主机:端口", ErrInvalid, i+1)
		}
		if seen[u.hostPort] {
			return nil, fmt.Errorf("%w：第 %d 台上游 %q 重复", ErrInvalid, i+1, u.hostPort)
		}
		seen[u.hostPort] = true
		weight := up.Weight
		if weight == 0 {
			weight = 1
		}
		if weight < 1 || weight > maxUpstreamWeight {
			return nil, fmt.Errorf("%w：第 %d 台权重必须在 1-%d 之间", ErrInvalid, i+1, maxUpstreamWeight)
		}
		out = append(out, ProxyUpstream{Target: u.String(), Weight: weight})
	}
	return out, nil
}

// proxyActive reports whether either proxy form owns this site's location /.
// The single target and the balancing table are mutually exclusive, but every
// exclusion check elsewhere only cares that one of them is set.
func (s Site) proxyActive() bool {
	return s.ProxyTarget != "" || len(s.ProxyUpstreams) > 0
}

// upstreamName derives the http-level upstream block name from the site name.
// It shares the zone prefix mapping, which is injective on validated site
// names, and the _upstream suffix keeps it apart from the _req/_conn zones.
func upstreamName(site string) string {
	return limitZoneName(site) + "_upstream"
}

// upstreamRow is one site's balancing table in the http-level file.
type upstreamRow struct {
	Site      string
	Method    string
	Upstreams []ProxyUpstream
}

// renderUpstreams builds the whole http-context upstream table from the rows.
// An empty row list returns "", which callers must treat as "the file has to
// go away": a zero-byte file reached through an http-level include does not
// parse, exactly like the zone table.
func renderUpstreams(rows []upstreamRow) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(headerLine + "\n")
	b.WriteString(upstreamsMarkerLine + `{"kind":"proxy-upstreams","file_version":1}` + "\n")
	b.WriteString("# 本文件由 Mini Panel 生成：负载均衡的 upstream 块必须定义在 http 上下文，\n")
	b.WriteString("# 因此集中写在这里。请勿手工编辑：面板在任何多上游改动时整表重写，最后一个多上游站点消失时会删除本文件。\n")
	b.WriteString("# 站点的 vhost 只 proxy_pass 到本文件定义的 upstream 名；nginx -t 会拒绝引用了不存在 upstream 的配置。\n")
	for _, row := range rows {
		b.WriteString("upstream " + upstreamName(row.Site) + " {\n")
		if row.Method != "" {
			b.WriteString("    " + row.Method + ";\n")
		}
		for _, up := range row.Upstreams {
			hostPort := strings.TrimPrefix(up.Target, "http://")
			line := "    server " + hostPort
			if up.Weight > 1 {
				line += fmt.Sprintf(" weight=%d", up.Weight)
			}
			b.WriteString(line + ";\n")
		}
		b.WriteString("}\n")
	}
	return b.String()
}

// parseUpstreamsMarker reports whether a file is an upstream table the panel
// owns. A hand-made file of the same name without the marker keeps its bytes.
func parseUpstreamsMarker(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, upstreamsMarkerLine) {
			continue
		}
		return strings.Contains(line, `"kind":"proxy-upstreams"`)
	}
	return false
}

// upstreamsPath resolves where the upstream table may be written, reusing the
// zone table's include discovery: the same evidence ("the host's own config
// globs this directory at http level") answers for both kinds of file.
func (m *Manager) upstreamsPath() (string, error) {
	p, err := m.limitsPathIn(upstreamsFileName)
	if err != nil {
		return "", fmt.Errorf("%w：本机 nginx.conf 里没有通配形式的 http 级 include（例如 sites-enabled/* 或 conf.d/*.conf），"+
			"负载均衡的 upstream 块必须定义在 http 上下文，面板不会猜测一个它无法确认会被读取的位置", ErrInvalid)
	}
	return p, nil
}

// upstreamsFileExists reports whether an upstream table is already on disk
// under any directory this host's config could include it from.
func (m *Manager) upstreamsFileExists() bool {
	for _, dir := range []string{m.Layout.Dir(), filepath.Join(m.Layout.ConfigDir, "sites-enabled")} {
		if _, existed := readMaybe(filepath.Join(dir, upstreamsFileName)); existed {
			return true
		}
	}
	return false
}

// upstreamRows is the upstream table's source of truth: every panel-owned site
// that carries a balancing table, with one site's table swapped in or a site
// removed. Deriving it from the list keeps a vhost and its upstream definition
// from disagreeing after a crash or a hand edit.
func (m *Manager) upstreamRows(replaceName string, replace []ProxyUpstream, replaceMethod string, skipNames ...string) ([]upstreamRow, error) {
	sites, err := m.List()
	if err != nil {
		return nil, fmt.Errorf("列出站点以生成 upstream 表: %w", err)
	}
	skip := make(map[string]bool, len(skipNames))
	for _, n := range skipNames {
		skip[n] = true
	}
	rows := []upstreamRow{}
	for _, s := range sites {
		if skip[s.Name] {
			continue
		}
		if s.Name == replaceName {
			if len(replace) > 0 {
				rows = append(rows, upstreamRow{Site: s.Name, Method: replaceMethod, Upstreams: replace})
			}
			continue
		}
		if len(s.ProxyUpstreams) > 0 {
			rows = append(rows, upstreamRow{Site: s.Name, Method: s.ProxyLBMethod, Upstreams: s.ProxyUpstreams})
		}
	}
	return rows, nil
}

// SetProxyUpstreams replaces or clears a site's multi-upstream balancing
// table. Clearing (an empty table) is always allowed and returns the site to
// whatever its single-target proxy or static handler says. A non-empty table
// owns `location /` exactly like the single-target proxy, so it is mutually
// exclusive with rewrite templates, site-wide redirect and hotlink protection;
// it also replaces any single ProxyTarget, because two proxy owners would make
// the rendered config depend on line order.
func (m *Manager) SetProxyUpstreams(name string, ups []ProxyUpstream, method string, websocket bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	ups, err := normalizeProxyUpstreams(ups)
	if err != nil {
		return Site{}, err
	}
	method, err = normalizeProxyLBMethod(method)
	if err != nil {
		return Site{}, err
	}
	if len(ups) == 0 {
		if websocket {
			return Site{}, fmt.Errorf("%w：启用 WebSocket 支持前必须先填写上游服务器", ErrInvalid)
		}
		method = ""
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if len(ups) > 0 {
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
	rows, err := m.upstreamRows(name, ups, method)
	if err != nil {
		return Site{}, err
	}
	site.ProxyTarget = ""
	site.ProxyUpstreams = ups
	site.ProxyLBMethod = method
	site.ProxyWebSocket = websocket
	body := render(site)
	table := renderUpstreams(rows)
	files := []configFile{{Path: site.ConfigPath, Body: &body}}
	if len(rows) > 0 || m.upstreamsFileExists() {
		tablePath, err := m.upstreamsPath()
		if err != nil {
			return Site{}, err
		}
		files = append(files, configFile{Path: tablePath, Body: &table, OwnedCheck: parseUpstreamsMarker})
	}
	if err := m.applyFiles(files); err != nil {
		return Site{}, err
	}
	return site, nil
}
