package nginx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Traffic limiting is the fifteenth slice of M2. nginx keeps the shared memory
// zones in the `http` context, outside any server block, while the panel owns
// only the per-site vhost. So this feature writes two files in one transaction:
// the site's vhost (which gets the fixed `limit_req` / `limit_conn` directives)
// and a panel-owned zone table that has to live in a directory nginx already
// includes at `http` level. Neither file can be written on its own: a vhost
// naming a zone the table does not define is a config nginx refuses to reload,
// and that is exactly the failure this two-file discipline exists to make
// impossible.
//
// The caller supplies four things: a request rate, a burst, a connection cap
// and a status. Everything else — the zone name, the key
// ($binary_remote_addr) and the size of each zone — is decided here, so no
// request can smuggle a directive into the http context.

const (
	// limitsFileSuffix carries no dot on purpose: sites-enabled is globbed as
	// `include sites-enabled/*`, and a Debian nginx.conf may additionally
	// include `sites-enabled/*.conf`. A dotless name is matched by the first
	// glob and never by the second, so the zone table gets included exactly
	// once instead of twice — twice would fail as a duplicate zone.
	limitsFileSuffix = "conf"
	limitsMarkerLine = "# minipanel-limits: "
	// zoneSize is fixed rather than offered: it is the one part of a zone
	// definition that does not change what the operator is asking for.
	zoneSize = "10m"

	minLimitRate        = 1
	maxLimitRate        = 1_000_000
	maxLimitBurst       = 100_000
	maxLimitConnections = 100_000
)

var (
	// limitZoneRe is also the marker validator: a zone name that cannot be
	// rendered safely must make the file foreign rather than be written into
	// the http context.
	limitZoneRe = regexp.MustCompile(`^mp_[a-z0-9_]{1,63}$`)
	// limitCommentTextRe is the only text allowed into the zone table's human
	// comment. The file is config, so a newline in here would be a directive.
	limitCommentTextRe = regexp.MustCompile(`[^A-Za-z0-9.:-]`)
	limitRateUnitRe    = regexp.MustCompile(`^[1-9][0-9]*[rm](/[sm])?$`)
)

// TrafficLimit is one site's traffic ceiling. RequestRate is empty when the
// site is not request-rate limited; Burst is only meaningful together with a
// rate, because nginx takes it on the `limit_req` line. Connections caps
// concurrent connections per client address, and Status is what nginx returns
// when either limit is exceeded.
type TrafficLimit struct {
	RequestRate string `json:"request_rate,omitempty"`
	Burst       int    `json:"burst,omitempty"`
	Connections int    `json:"connections,omitempty"`
	Status      int    `json:"status,omitempty"`
}

// active reports whether a normalized limit needs any nginx directive at all.
// It is the single test used by the vhost renderer, the marker and the zone
// table, so the three cannot disagree about what "limited" means.
func (l TrafficLimit) active() bool {
	return l.RequestRate != "" || l.Connections != 0
}

// normalizeTrafficLimit validates a request-shaped limit and returns the
// canonical form stored in the marker and rendered into nginx. An empty limit
// is the clear operation and is always allowed.
func normalizeTrafficLimit(in TrafficLimit) (TrafficLimit, error) {
	out := TrafficLimit{
		RequestRate: strings.ToLower(strings.TrimSpace(in.RequestRate)),
		Burst:       in.Burst,
		Connections: in.Connections,
		Status:      in.Status,
	}
	if out.RequestRate == "" && out.Burst == 0 && out.Connections == 0 && out.Status == 0 {
		return TrafficLimit{}, nil
	}
	// Either half may stand alone: a connection cap without a request rate is a
	// complete limit, so refusing it would only push operators to invent a rate.
	if out.RequestRate == "" && out.Connections == 0 {
		return TrafficLimit{}, fmt.Errorf("%w：至少要给出请求速率上限或单 IP 并发连接数中的一个，否则限流状态码与突发值都没有作用", ErrInvalid)
	}
	if out.RequestRate != "" {
		if !limitRateUnitRe.MatchString(out.RequestRate) {
			return TrafficLimit{}, fmt.Errorf("%w：请求速率上限需要是 10r/s、200r/m、100r 这类形状，数值范围 %d-%d",
				ErrInvalid, minLimitRate, maxLimitRate)
		}
		digits := strings.TrimSuffix(strings.TrimSuffix(out.RequestRate, "/s"), "/m")
		digits = strings.TrimSuffix(digits, "r")
		n, err := strconv.Atoi(digits)
		if err != nil || n < minLimitRate || n > maxLimitRate {
			return TrafficLimit{}, fmt.Errorf("%w：请求速率上限的数值必须在 %d-%d 之间", ErrInvalid, minLimitRate, maxLimitRate)
		}
	} else if out.Burst != 0 {
		return TrafficLimit{}, fmt.Errorf("%w：突发值只在设置了请求速率上限时才有意义", ErrInvalid)
	}
	if out.Burst < 0 || out.Burst > maxLimitBurst {
		return TrafficLimit{}, fmt.Errorf("%w：突发值不能超过 %d", ErrInvalid, maxLimitBurst)
	}
	if out.Connections < 0 || out.Connections > maxLimitConnections {
		return TrafficLimit{}, fmt.Errorf("%w：单 IP 并发连接数不能超过 %d", ErrInvalid, maxLimitConnections)
	}
	if out.Status != 0 && out.Status != 429 && out.Status != 503 {
		return TrafficLimit{}, fmt.Errorf("%w：限流状态码只支持 429 与 503，留空表示用 nginx 默认的 503", ErrInvalid)
	}
	return out, nil
}

// limitZoneName turns a validated site name into a zone name prefix. The
// mapping is injective on purpose: site names match ^[a-z][a-z0-9-]{1,31}$, so
// replacing the hyphens cannot make two sites share a zone, and a leftover
// zone can never be picked up by a different site.
func limitZoneName(site string) string {
	return "mp_" + strings.ReplaceAll(site, "-", "_")
}

// trafficLimitLines renders the server-level directives for one site. The zone
// names are derived from the site name, so a vhost cannot reference a zone the
// table does not define — as long as the table is rebuilt from the site list.
func trafficLimitLines(site string, l TrafficLimit) string {
	if !l.active() {
		return ""
	}
	var b strings.Builder
	zone := limitZoneName(site)
	if l.RequestRate != "" {
		if l.Burst > 0 {
			b.WriteString("    limit_req zone=" + zone + "_req burst=" +
				strconv.Itoa(l.Burst) + " nodelay;\n")
		} else {
			b.WriteString("    limit_req zone=" + zone + "_req;\n")
		}
	}
	if l.Connections != 0 {
		b.WriteString("    limit_conn " + zone + "_conn " + strconv.Itoa(l.Connections) + ";\n")
	}
	if l.Status != 0 {
		b.WriteString("    limit_req_status " + strconv.Itoa(l.Status) + ";\n")
		b.WriteString("    limit_conn_status " + strconv.Itoa(l.Status) + ";\n")
	}
	return b.String()
}

// limitZoneRow is one row of the zone table: a site and its normalized limit.
type limitZoneRow struct {
	Site  string
	Limit TrafficLimit
}

// renderLimits builds the whole http-context zone table from the rows. An
// empty row list returns "", which callers must treat as "the file has to go
// away": a zero-byte file reached through `include conf.d/*.conf` does not
// parse at http level, so removing it is a correctness requirement and not
// tidiness.
func renderLimits(rows []limitZoneRow) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(headerLine + "\n")
	b.WriteString(limitsMarkerLine + `{"kind":"traffic-limits","file_version":1}` + "\n")
	b.WriteString("# 本文件由 Mini Panel 生成：各站点限流所用的共享内存区（zone）必须定义在 http 上下文，\n")
	b.WriteString("# 因此集中写在这里。请勿手工编辑：面板在任何限流改动时整表重写，最后一个限流消失时会删除本文件。\n")
	b.WriteString("# 站点的 vhost 只引用本文件定义的 zone 名；nginx -t 会拒绝引用了不存在的 zone 的配置。\n")
	for _, row := range rows {
		zone := limitZoneName(row.Site)
		suffix := ""
		if safe := limitCommentTextRe.ReplaceAllString(row.Site, ""); safe != "" {
			suffix = "  # 站点 " + safe
		}
		if row.Limit.RequestRate != "" {
			b.WriteString("limit_req_zone $binary_remote_addr zone=" + zone + "_req:" + zoneSize +
				" rate=" + row.Limit.RequestRate + ";" + suffix + "\n")
		}
		if row.Limit.Connections != 0 {
			b.WriteString("limit_conn_zone $binary_remote_addr zone=" + zone + "_conn:" + zoneSize +
				";" + suffix + "\n")
		}
	}
	return b.String()
}

// parseLimitsMarker reports whether a file is a zone table the panel owns. A
// file that carries our header prose but no table marker is still not ours to
// overwrite — that is how a hand-made file of the same name keeps its bytes.
func parseLimitsMarker(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, limitsMarkerLine) {
			continue
		}
		return strings.Contains(line, `"kind":"traffic-limits"`)
	}
	return false
}

// limitsFromMarker copies the already-validated limit out of a marker payload.
// parseMarker normalizes limits on the way in, so a vhost on disk can never
// name a zone the table would not define; this is a copy, not a second
// validator.
func limitsFromMarker(p markerPayload) *TrafficLimit {
	if p.Limits == nil || !p.Limits.active() {
		return nil
	}
	keep := *p.Limits
	return &keep
}

// limitsFileName is the zone table's name. The suffix deliberately carries no
// dot: a Debian nginx.conf may include both `sites-enabled/*` and
// `sites-enabled/*.conf`, and a file matched twice would define its zones
// twice — which nginx refuses.
const limitsFileName = filePrefix + "limits" + "." + limitsFileSuffix

// httpIncludeDirs lists the directories the host's own nginx.conf includes with
// a wildcard. That list is the only honest answer to "where may the panel put a
// file that must sit in the http context", because the panel does not get to
// choose how nginx was installed: the standard Debian layout includes
// sites-enabled/* while RHEL and OpenResty include conf.d/*.conf, and a host
// can use either, both, or neither.
//
// Directories are returned in the order they appear in the config, and a glob
// ending in `.conf` is reported as such so callers can tell "included by any
// glob" from "included only by a dotted glob".
func httpIncludeDirs(configDir string) []httpInclude {
	b, err := os.ReadFile(filepath.Join(configDir, "nginx.conf"))
	if err != nil {
		return nil
	}
	out := []httpInclude{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "include") {
			continue
		}
		pattern := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "include")), ";")
		pattern = strings.Trim(pattern, `"'`)
		if pattern == "" || !strings.Contains(pattern, "*") {
			continue
		}
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(configDir, pattern)
		}
		clean := filepath.Clean(pattern)
		glob := filepath.Base(clean)
		dir := filepath.Dir(clean)
		if glob == "*" || glob == "*.conf" {
			out = append(out, httpInclude{Dir: dir, Glob: glob})
		}
	}
	return out
}

// httpInclude is one wildcard include the host's nginx.conf declares.
type httpInclude struct {
	Dir  string
	Glob string
}

// covers reports whether this include would pick up the given file name.
func (h httpInclude) covers(name string) bool {
	if h.Glob == "*" {
		return true
	}
	return h.Glob == "*.conf" && strings.HasSuffix(name, ".conf")
}

// limitsPath resolves where the zone table may be written, as a pair of
// (directory, name) the host's own config proves is included at http level. It
// prefers a directory that already carries the panel's vhosts, because that is
// the strongest available evidence: a file there is already being read by this
// nginx at http level.
//
// When no include glob covers any candidate directory, the panel refuses:
// guessing a location for an http-level file would produce a config nginx does
// not read at all, which is worse than not offering the feature.
func (m *Manager) limitsPath() (string, error) {
	return m.limitsPathIn(limitsFileName)
}

func (m *Manager) limitsPathIn(name string) (string, error) {
	includes := httpIncludeDirs(m.Layout.ConfigDir)
	preferred := []string{m.Layout.Dir()}
	if m.Layout.Enabled != "" {
		// In the Debian layout the vhosts are only live through sites-enabled,
		// so that is the directory the glob include actually reads.
		preferred = append(preferred, m.Layout.Enabled)
	}
	for _, cand := range preferred {
		for _, inc := range includes {
			if inc.Glob == "*" && sameDir(inc.Dir, cand) {
				return filepath.Join(cand, name), nil
			}
		}
	}
	for _, cand := range preferred {
		for _, inc := range includes {
			if inc.covers(name) && sameDir(inc.Dir, cand) {
				return filepath.Join(cand, name), nil
			}
		}
	}
	for _, inc := range includes {
		if inc.covers(name) {
			return filepath.Join(inc.Dir, name), nil
		}
	}
	return "", fmt.Errorf("%w：本机 nginx.conf 里没有通配形式的 http 级 include（例如 sites-enabled/* 或 conf.d/*.conf），"+
		"限流所需的共享内存区必须定义在 http 上下文，面板不会猜测一个它无法确认会被读取的位置", ErrInvalid)
}

func sameDir(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// limitsFileExists reports whether a zone table is already on disk, under any
// of the directories this host's config could include it from. Deleting a
// never-limited site on a host that has no such file must not need to resolve
// the path at all.
func (m *Manager) limitsFileExists() bool {
	for _, dir := range []string{m.Layout.Dir(), filepath.Join(m.Layout.ConfigDir, "sites-enabled")} {
		if _, existed := readMaybe(filepath.Join(dir, limitsFileName)); existed {
			return true
		}
	}
	return false
}

// writeOwned writes a file the panel has just checked it owns, creating the
// parent directory when the layout is fresh.
func writeOwned(path, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	return writeAtomic(path, []byte(body), 0o644)
}

// applyFiles runs the panel's test-before-reload protocol over a set of files
// at once. A body of nil means "this file must not be there"; a non-nil empty
// body means the same. Every file in the set is restored to its exact previous
// bytes — or removed again if it did not exist — when a write, `nginx -t` or
// the reload fails, so no subset of a multi-file change can survive.
//
// applyConfig is the single-file case of the same rule.
func (m *Manager) applyFiles(files []configFile) error {
	for _, f := range files {
		if f.Body == nil || *f.Body == "" {
			continue
		}
		prev, existed := readMaybe(f.Path)
		if existed && f.OwnedCheck != nil && !f.OwnedCheck(string(prev)) {
			return fmt.Errorf("%w：%s 不是面板生成的文件，面板不会覆盖它", ErrInvalid, f.Path)
		}
	}

	changed := false
	for _, f := range files {
		prev, existed := readMaybe(f.Path)
		if f.Body == nil || *f.Body == "" {
			if existed {
				changed = true
				break
			}
			continue
		}
		if !existed || string(prev) != *f.Body {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}

	// Every vhost now names per-site log files; the directory must exist and
	// be worker-writable before nginx is asked to test or reload them.
	if err := m.ensureLogDir(); err != nil {
		return err
	}

	snapshots := make([]fileSnapshot, 0, len(files))
	for _, f := range files {
		prev, existed := readMaybe(f.Path)
		snapshots = append(snapshots, fileSnapshot{path: f.Path, prev: prev, existed: existed})
		var err error
		if f.Body == nil || *f.Body == "" {
			err = os.Remove(f.Path)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		} else {
			err = writeOwned(f.Path, *f.Body)
		}
		if err != nil {
			rollbackFiles(snapshots)
			return fmt.Errorf("写入配置: %w", err)
		}
	}
	if out, err := m.TestConfig(); err != nil {
		rollbackFiles(snapshots)
		return fmt.Errorf("%w：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		rollbackFiles(snapshots)
		return fmt.Errorf("%w：reload 失败：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	return nil
}

// rollbackFiles puts a set of files back exactly as found, in reverse order.
func rollbackFiles(snapshots []fileSnapshot) {
	for i := len(snapshots) - 1; i >= 0; i-- {
		s := snapshots[i]
		restoreFile(s.path, s.prev, s.existed, 0o644)
	}
}

// limitsRows is the zone table's source of truth: every panel-owned site that
// carries a limit, with one site's limit swapped in or a site removed.
// Deriving the table from the list rather than from the request is what keeps a
// vhost and a zone definition from disagreeing after a crash or a hand edit.
func (m *Manager) limitsRows(replaceName string, replace *TrafficLimit, skipNames ...string) ([]limitZoneRow, error) {
	sites, err := m.List()
	if err != nil {
		return nil, fmt.Errorf("列出站点以生成限流表: %w", err)
	}
	skip := make(map[string]bool, len(skipNames))
	for _, n := range skipNames {
		skip[n] = true
	}
	rows := []limitZoneRow{}
	for _, s := range sites {
		if skip[s.Name] {
			continue
		}
		if s.Name == replaceName {
			if replace != nil && replace.active() {
				rows = append(rows, limitZoneRow{Site: s.Name, Limit: *replace})
			}
			continue
		}
		if s.Limits != nil && s.Limits.active() {
			rows = append(rows, limitZoneRow{Site: s.Name, Limit: *s.Limits})
		}
	}
	return rows, nil
}

// SetLimits replaces or clears one site's traffic limits. Limits are server-
// level directives: they do not own `location /`, so they coexist with
// pseudo-static templates, reverse proxy, site-wide redirect, exact-path
// redirects, hotlink protection, Basic Auth, real IP resolution and PHP
// binding. Clearing is always allowed, including when the zone table has to be
// deleted along with the last limit on the host.
func (m *Manager) SetLimits(name string, in TrafficLimit) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	limit, err := normalizeTrafficLimit(in)
	if err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	rows, err := m.limitsRows(name, &limit)
	if err != nil {
		return Site{}, err
	}
	if limit.active() {
		keep := limit
		site.Limits = &keep
	} else {
		site.Limits = nil
	}
	body := render(site)
	table := renderLimits(rows)
	files := []configFile{{Path: site.ConfigPath, Body: &body}}
	if len(rows) > 0 || m.limitsFileExists() {
		tablePath, err := m.limitsPath()
		if err != nil {
			return Site{}, err
		}
		files = append(files, configFile{Path: tablePath, Body: &table, OwnedCheck: parseLimitsMarker})
	}
	if err := m.applyFiles(files); err != nil {
		return Site{}, err
	}
	return site, nil
}
