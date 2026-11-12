package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Proxy response caching is the twenty-fifth slice of M2, closing the last
// "未交付" note on the reverse-proxy row of the feature matrix (功能设计.md
// §3: 反向代理…缓存开关). The operator supplies three numbers — a validity
// window, a disk cap and an inactive-eviction window — and the panel renders
// a fixed cache block around whichever proxy form owns location /.
//
// Like the traffic-limit zones and the upstream table, proxy_cache_path must
// live in the http context, so the definitions go into a panel-owned table
// file placed through the same include discovery, written in the same
// test-before-reload transaction as the vhost. The cache files themselves
// live under CacheDir (host state, derived from the site name, never marker
// data), one directory per site so dropping a cache can remove its bytes.
//
// Boundaries stated rather than hidden: only GET/HEAD are cached; only 200
// and 302 responses are stored (301 is deliberately not cached — a permanent
// redirect change would otherwise keep being served from disk); nginx's own
// rules still apply on top (responses with Set-Cookie or private/no-store
// Cache-Control are not cached, and the panel does not override them);
// responses to requests carrying Authorization or Cookie headers are passed
// through uncached, so one visitor's personalised page can never be served
// to another. The cache key includes the Host header, so two domains on one
// vhost do not share entries.

const (
	// cacheFile follows the zone table's dotless-suffix naming rule so a
	// Debian host including both sites-enabled/* and sites-enabled/*.conf
	// reads it exactly once.
	cacheFileName   = filePrefix + "proxy-cache." + limitsFileSuffix
	cacheMarkerLine = "# minipanel-proxy-cache: "
	// cacheZoneSize is fixed: the keys zone size does not change what the
	// operator asked for, same reasoning as the traffic-limit zoneSize.
	cacheZoneSize = "10m"

	minCacheValidSeconds   = 1
	maxCacheValidSeconds   = 86400 * 30
	minCacheMaxSizeMB      = 10
	maxCacheMaxSizeMB      = 102400
	minCacheInactiveMinute = 1
	maxCacheInactiveMinute = 60 * 24 * 30
)

// ProxyCache is one site's response-cache policy. ValidSeconds is how long a
// stored 200/302 stays fresh; MaxSizeMB caps the on-disk cache; InactiveMinutes
// evicts entries not requested for that long even while fresh. Nil means no
// cache. The zone name and the cache directory are derived from the site name
// and the Manager, never supplied by a request.
type ProxyCache struct {
	ValidSeconds    int `json:"valid_seconds"`
	MaxSizeMB       int `json:"max_size_mb"`
	InactiveMinutes int `json:"inactive_minutes"`
}

// normalizeProxyCache validates a request-shaped policy. A nil pointer is the
// clear operation and is always allowed; a non-nil policy must carry all three
// numbers in range — there are no silent defaults, because "how long is this
// page served stale" must be a decision the operator actually made.
func normalizeProxyCache(in *ProxyCache) (*ProxyCache, error) {
	if in == nil {
		return nil, nil
	}
	if in.ValidSeconds < minCacheValidSeconds || in.ValidSeconds > maxCacheValidSeconds {
		return nil, fmt.Errorf("%w：缓存有效期必须在 %d-%d 秒之间", ErrInvalid, minCacheValidSeconds, maxCacheValidSeconds)
	}
	if in.MaxSizeMB < minCacheMaxSizeMB || in.MaxSizeMB > maxCacheMaxSizeMB {
		return nil, fmt.Errorf("%w：缓存磁盘上限必须在 %d-%d MB 之间", ErrInvalid, minCacheMaxSizeMB, maxCacheMaxSizeMB)
	}
	if in.InactiveMinutes < minCacheInactiveMinute || in.InactiveMinutes > maxCacheInactiveMinute {
		return nil, fmt.Errorf("%w：缓存闲置淘汰时间必须在 %d-%d 分钟之间", ErrInvalid, minCacheInactiveMinute, maxCacheInactiveMinute)
	}
	keep := *in
	return &keep, nil
}

// cacheZoneName derives the shared keys-zone name. It shares the injective
// site-name mapping with the limit zones and upstream blocks; the _cache
// suffix keeps the three kinds apart.
func cacheZoneName(site string) string {
	return limitZoneName(site) + "_cache"
}

// cacheDirFor is where one site's cached bytes live. Like the log paths it is
// derived host state: a tampered marker cannot move where cache files are
// written or which directory a clear removes.
func (m *Manager) cacheDirFor(site string) string {
	return filepath.Join(m.CacheDir, site)
}

// proxyCacheLines renders the fixed location-level directives. They are only
// ever called for a site whose location / is a proxy block, so the directives
// always have a proxy_pass beside them.
func proxyCacheLines(s Site) string {
	c := s.ProxyCache
	var b strings.Builder
	b.WriteString("        proxy_cache " + cacheZoneName(s.Name) + ";\n")
	b.WriteString("        proxy_cache_key \"$scheme|$host|$request_method|$request_uri\";\n")
	b.WriteString("        proxy_cache_methods GET HEAD;\n")
	fmt.Fprintf(&b, "        proxy_cache_valid 200 302 %ds;\n", c.ValidSeconds)
	b.WriteString("        proxy_cache_lock on;\n")
	// Personalised requests bypass the cache in both directions: they are
	// neither served from it nor stored into it.
	b.WriteString("        proxy_cache_bypass $http_authorization $http_cookie;\n")
	b.WriteString("        proxy_no_cache $http_authorization $http_cookie;\n")
	b.WriteString("        add_header X-Cache-Status $upstream_cache_status always;\n")
	return b.String()
}

// cacheRow is one site's policy in the http-level table.
type cacheRow struct {
	Site  string
	Cache ProxyCache
	Path  string
}

// renderProxyCacheTable builds the whole http-context table from the rows. An
// empty row list returns "", which callers must treat as "the file has to go
// away": a zero-byte file reached through an http-level include does not
// parse, exactly like the zone and upstream tables.
func renderProxyCacheTable(rows []cacheRow) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(headerLine + "\n")
	b.WriteString(cacheMarkerLine + `{"kind":"proxy-cache","file_version":1}` + "\n")
	b.WriteString("# 本文件由 Mini Panel 生成：反向代理缓存的 proxy_cache_path 必须定义在 http 上下文，\n")
	b.WriteString("# 因此集中写在这里。请勿手工编辑：面板在任何缓存改动时整表重写，最后一个缓存站点消失时会删除本文件。\n")
	b.WriteString("# 站点的 vhost 只引用本文件定义的 zone 名；nginx -t 会拒绝引用了不存在 zone 的配置。\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "proxy_cache_path %s levels=1:2 keys_zone=%s:%s max_size=%dm inactive=%dm use_temp_path=off;\n",
			row.Path, cacheZoneName(row.Site), cacheZoneSize, row.Cache.MaxSizeMB, row.Cache.InactiveMinutes)
	}
	return b.String()
}

// parseCacheMarker reports whether a file is a cache table the panel owns. A
// hand-made file of the same name without the marker keeps its bytes.
func parseCacheMarker(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, cacheMarkerLine) {
			continue
		}
		return strings.Contains(line, `"kind":"proxy-cache"`)
	}
	return false
}

// cacheTablePath resolves where the table may be written, reusing the zone
// table's include discovery: the same evidence answers for all three kinds of
// http-level file.
func (m *Manager) cacheTablePath() (string, error) {
	p, err := m.limitsPathIn(cacheFileName)
	if err != nil {
		return "", fmt.Errorf("%w：本机 nginx.conf 里没有通配形式的 http 级 include（例如 sites-enabled/* 或 conf.d/*.conf），"+
			"反向代理缓存的 proxy_cache_path 必须定义在 http 上下文，面板不会猜测一个它无法确认会被读取的位置", ErrInvalid)
	}
	return p, nil
}

// cacheTableExists reports whether a cache table is already on disk under any
// directory this host's config could include it from.
func (m *Manager) cacheTableExists() bool {
	for _, dir := range []string{m.Layout.Dir(), filepath.Join(m.Layout.ConfigDir, "sites-enabled")} {
		if _, existed := readMaybe(filepath.Join(dir, cacheFileName)); existed {
			return true
		}
	}
	return false
}

// cacheRows is the table's source of truth: every panel-owned site that has a
// proxy owner AND a cache policy, with one site's policy swapped in or a site
// removed. Deriving it from the list keeps a vhost and a cache definition from
// disagreeing after a crash or a hand edit.
func (m *Manager) cacheRows(replaceName string, replace *ProxyCache, skipNames ...string) ([]cacheRow, error) {
	sites, err := m.List()
	if err != nil {
		return nil, fmt.Errorf("列出站点以生成代理缓存表: %w", err)
	}
	skip := make(map[string]bool, len(skipNames))
	for _, n := range skipNames {
		skip[n] = true
	}
	rows := []cacheRow{}
	for _, s := range sites {
		if skip[s.Name] {
			continue
		}
		if !s.proxyActive() {
			continue
		}
		c := s.ProxyCache
		if s.Name == replaceName {
			c = replace
		}
		if c != nil {
			rows = append(rows, cacheRow{Site: s.Name, Cache: *c, Path: m.cacheDirFor(s.Name)})
		}
	}
	return rows, nil
}

// cacheTableFile adds the rebuilt cache table to a transaction when any row
// survives or a table file exists that may need updating or removal. Hosts
// with no cache at all never resolve the path, so the include probe does not
// become a new precondition for unrelated writes.
func (m *Manager) cacheTableFile(rows []cacheRow, files []configFile) ([]configFile, error) {
	if len(rows) == 0 && !m.cacheTableExists() {
		return files, nil
	}
	tablePath, err := m.cacheTablePath()
	if err != nil {
		return nil, err
	}
	table := renderProxyCacheTable(rows)
	if len(rows) > 0 {
		if err := m.ensureCacheRoot(); err != nil {
			return nil, err
		}
	}
	return append(files, configFile{Path: tablePath, Body: &table, OwnedCheck: parseCacheMarker}), nil
}

// ensureCacheRoot prepares the ground for nginx: nginx creates each site's
// leaf cache directory itself (chowned to the worker user), but it neither
// creates missing parents nor traverses a 0700 ancestor, and the panel's own
// footprint directories are created 0700. The cache root is created 0755 and
// every ancestor gets the two execute bits added if missing — never read or
// write, so directory listings stay as private as they were.
func (m *Manager) ensureCacheRoot() error {
	if m.CacheDir == "" {
		return nil
	}
	if err := os.MkdirAll(m.CacheDir, 0o755); err != nil {
		return fmt.Errorf("创建缓存根目录失败：%w", err)
	}
	for d := m.CacheDir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return fmt.Errorf("检查缓存目录失败：%w", err)
		}
		if mode := fi.Mode(); mode&0o011 != 0o011 {
			if err := os.Chmod(d, mode|0o011); err != nil {
				return fmt.Errorf("缓存目录无法开放给 nginx 工作进程进入：%w", err)
			}
		}
		if parent := filepath.Dir(d); parent == d {
			return nil
		}
	}
}

// removeCacheDir drops one site's cached bytes after a successful clear or
// delete. It is data, not config: removal happens only after the transaction
// committed, and a removal failure does not fail the operation (the next
// enable recreates the directory; stale files are unreachable without a zone).
func (m *Manager) removeCacheDir(site string) {
	if m.CacheDir == "" {
		return
	}
	_ = os.RemoveAll(m.cacheDirFor(site))
}

// SetProxyCache enables, replaces or clears a site's response cache. Enabling
// requires a proxy owner (single target or balancing table): a cache on a
// static vhost would write directives nginx refuses. Clearing is always
// allowed and removes the site's cached bytes. The vhost and the http-level
// table commit in one test-before-reload transaction.
func (m *Manager) SetProxyCache(name string, in *ProxyCache) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	c, err := normalizeProxyCache(in)
	if err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if c != nil && !site.proxyActive() {
		return Site{}, fmt.Errorf("%w：响应缓存只对反向代理站点有意义；先启用反向代理或负载均衡，再开缓存", ErrInvalid)
	}
	rows, err := m.cacheRows(name, c)
	if err != nil {
		return Site{}, err
	}
	site.ProxyCache = c
	body := render(site)
	files := []configFile{{Path: site.ConfigPath, Body: &body}}
	files, err = m.cacheTableFile(rows, files)
	if err != nil {
		return Site{}, err
	}
	if err := m.applyFiles(files); err != nil {
		return Site{}, err
	}
	if c == nil {
		m.removeCacheDir(name)
	}
	return site, nil
}
