// Package nginx owns the only nginx files Mini Panel writes itself: one
// server-block config per site, always carrying a machine-readable marker so
// the panel can tell its own files apart from everything else in
// /etc/nginx. Foreign files are never edited, never deleted and never listed
// as if the panel owned them.
//
// The write protocol is "test before take effect": a new config is written,
// `nginx -t` is run, and only a passing test is followed by a reload. Any
// failure on the way puts the previous state back, so a rejected config can
// never be what the running server reloads into. That includes the reload
// itself: "config is valid" and "the server accepted it" are two separate
// facts and both have to hold before the operation reports success.
package nginx

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Marker prefixes the machine-readable line. The name is deliberately not the
// same as the human comment above it: parsing must not depend on prose.
const (
	markerLine = "# minipanel-site: "
	headerLine = "# Managed by Mini Panel — regenerated on every change; do not edit."
	filePrefix = "minipanel-"
	fileSuffix = ".conf"
)

// Errors callers branch on. They are sentinels because the API maps them onto
// HTTP status codes; the wrapped text stays human-readable.
var (
	ErrExists         = errors.New("同名站点已存在")
	ErrNotFound       = errors.New("面板没有管理这个站点（不存在，或不是面板创建的）")
	ErrInvalid        = errors.New("站点参数不合法")
	ErrConfigRejected = errors.New("nginx 校验未通过，改动已回滚")
)

// Mode says where site files live on this host.
type Mode string

const (
	// ModeSites is the Debian/Ubuntu layout: sites-available plus a symlink in
	// sites-enabled. The symlink is the on/off switch.
	ModeSites Mode = "sites"
	// ModeConfD is the RHEL/openresty layout: *.conf in conf.d, no symlink.
	ModeConfD Mode = "conf.d"
)

// Layout is the discovered on-disk shape of one nginx installation.
type Layout struct {
	ConfigDir string
	Available string
	Enabled   string
	ConfD     string
	Mode      Mode
}

// Dir returns the directory site files are written to.
func (l Layout) Dir() string {
	if l.Mode == ModeConfD {
		return l.ConfD
	}
	return l.Available
}

// FileName is the on-disk name for a panel site. The prefix is the ownership
// proof at the directory level; the marker inside the file is the proof per
// file, because a file can be copied around.
func FileName(name string) string { return filePrefix + name + fileSuffix }

// ConfigPath is where the site's server block lives.
func (l Layout) ConfigPath(name string) string {
	return filepath.Join(l.Dir(), FileName(name))
}

// LinkPath is the sites-enabled symlink, empty in conf.d mode.
func (l Layout) LinkPath(name string) string {
	if l.Mode != ModeSites {
		return ""
	}
	return filepath.Join(l.Enabled, FileName(name))
}

// Detect discovers the layout under base (usually /etc/nginx). It requires the
// directory to exist: "nginx is installed but has no config tree" is not a
// state the writer can work with, and pretending otherwise produces a site
// list that is always empty.
func Detect(base string) (Layout, error) {
	if base == "" {
		base = "/etc/nginx"
	}
	st, err := os.Stat(base)
	if err != nil || !st.IsDir() {
		return Layout{}, fmt.Errorf("nginx 配置目录 %s 不存在", base)
	}
	avail := filepath.Join(base, "sites-available")
	enabled := filepath.Join(base, "sites-enabled")
	if isDir(avail) && isDir(enabled) {
		return Layout{ConfigDir: base, Available: avail, Enabled: enabled, Mode: ModeSites}, nil
	}
	confd := filepath.Join(base, "conf.d")
	if isDir(confd) {
		return Layout{ConfigDir: base, ConfD: confd, Mode: ModeConfD}, nil
	}
	return Layout{}, fmt.Errorf("在 %s 下没有找到 sites-available/sites-enabled 或 conf.d", base)
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// Runner runs one external command and returns its combined output. It is a
// field on Manager so tests can prove the ordering "test → reload" without an
// nginx binary; production code passes ExecRunner.
type Runner func(name string, args ...string) ([]byte, error)

// ExecRunner is the production Runner.
func ExecRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Manager is the write side for one nginx installation.
type Manager struct {
	Layout   Layout
	SiteRoot string
	// CertDir holds the panel-managed certificate/key pairs. It is a separate
	// directory from the vhost files so deleting a site's config cannot be
	// confused with deleting somebody's certificate, and so the private key can
	// stay 0600 instead of inheriting the vhost's 0644.
	CertDir string
	// AuthDir holds the panel-managed htpasswd files, one per site. Like CertDir
	// it is outside the vhost tree so a config glob cannot mistake a password
	// file for a server block.
	AuthDir string
	// LogDir holds the panel-managed per-site access/error logs. It is host
	// state like AuthDir: the paths are derived from it on every read and are
	// never stored in the marker. The directory must exist and be writable by
	// the nginx worker before a vhost naming it is reloaded, which is what
	// ensureLogDir guarantees inside every config transaction.
	LogDir string
	// HistoryDir holds durable pre-write snapshots of every config file the
	// panel changes (功能设计 §5.2: snapshots are part of the write protocol
	// from M2 on). Empty disables the layer; when set, a failed snapshot
	// refuses the write — the panel must be able to undo before it changes.
	HistoryDir string
	// CacheDir is the parent of the per-site reverse-proxy cache directories.
	// Like LogDir it is host state: the paths are derived from it on every
	// render and never stored in the marker. nginx creates the per-site
	// subdirectories itself when it loads a proxy_cache_path definition.
	CacheDir string
	Run      Runner
	Now      func() time.Time
}

// New detects the layout and returns a usable Manager. siteRoot is the parent
// directory new document roots are created under. Certificates default to a
// subdirectory of the nginx config tree so tests and `make run` stay inside one
// scratch directory; the platform layer overrides it with the panel's own
// config directory on a real host.
func New(base, siteRoot string) (*Manager, error) {
	return NewWithCertDir(base, siteRoot, filepath.Join(base, "minipanel-certs"))
}

// NewWithCertDir is New with an explicit certificate directory.
func NewWithCertDir(base, siteRoot, certDir string) (*Manager, error) {
	return NewWithDirs(base, siteRoot, certDir, filepath.Join(base, "minipanel-auth"))
}

// NewWithDirs is the full constructor: the platform layer passes the panel's
// own certificate and credential directories instead of leaving them inside the
// nginx tree.
func NewWithDirs(base, siteRoot, certDir, authDir string) (*Manager, error) {
	return NewWithLogDir(base, siteRoot, certDir, authDir, filepath.Join(base, "minipanel-logs"))
}

// NewWithLogDir is NewWithDirs with an explicit per-site log directory. The
// platform layer passes a directory under the panel's own log root so site
// logs never land inside the nginx config tree.
func NewWithLogDir(base, siteRoot, certDir, authDir, logDir string) (*Manager, error) {
	return NewWithHistoryDir(base, siteRoot, certDir, authDir, logDir, "")
}

// NewWithHistoryDir is NewWithLogDir with the durable config-history directory
// (usually <DataDir>/config-history). An empty historyDir leaves the snapshot
// layer inert, which is what the unit harnesses and embedded uses want.
func NewWithHistoryDir(base, siteRoot, certDir, authDir, logDir, historyDir string) (*Manager, error) {
	l, err := Detect(base)
	if err != nil {
		return nil, err
	}
	if siteRoot == "" {
		siteRoot = "/www/wwwroot"
	}
	if certDir == "" {
		certDir = filepath.Join(base, "minipanel-certs")
	}
	if authDir == "" {
		authDir = filepath.Join(base, "minipanel-auth")
	}
	if logDir == "" {
		logDir = filepath.Join(base, "minipanel-logs")
	}
	return &Manager{Layout: l, SiteRoot: siteRoot, CertDir: certDir, AuthDir: authDir, LogDir: logDir, HistoryDir: historyDir,
		CacheDir: filepath.Join(base, "minipanel-cache"), Run: ExecRunner, Now: time.Now}, nil
}

// Site is one row of the site list: the facts the panel generated, not a
// re-parse of nginx's effective configuration.
type Site struct {
	Name       string   `json:"name"`
	Domains    []string `json:"domains"`
	Root       string   `json:"root"`
	ConfigPath string   `json:"config_path"`
	Enabled    bool     `json:"enabled"`
	CreatedAt  string   `json:"created_at"`
	TLS        *TLSInfo `json:"tls,omitempty"`
	// Index is the site's custom `index` list. Nil means nginx's default list
	// (or index.php first when PHP is bound); a non-empty list is rendered
	// verbatim, in order.
	Index []string `json:"index,omitempty"`
	// Rewrite is the id of one locally bundled rewrite template ("none" when
	// the site uses the default try_files). It is a closed vocabulary, never a
	// config fragment supplied by a request.
	Rewrite string `json:"rewrite,omitempty"`
	// ProxyTarget is the validated upstream URL when the site is a reverse
	// proxy. It is empty for ordinary sites. Rewrite and proxy are mutually
	// exclusive because both own `location /`.
	ProxyTarget    string `json:"proxy_target,omitempty"`
	ProxyWebSocket bool   `json:"proxy_websocket,omitempty"`
	// ProxyUpstreams is the multi-upstream balancing table (slice 20). It is
	// mutually exclusive with ProxyTarget — both own location / — and its
	// http-level upstream blocks live in a panel-owned table file written in
	// the same transaction as this vhost. ProxyLBMethod is the closed
	// balancing vocabulary ("" = weighted round-robin, ip_hash, least_conn).
	ProxyUpstreams []ProxyUpstream `json:"proxy_upstreams,omitempty"`
	ProxyLBMethod  string          `json:"proxy_lb_method,omitempty"`
	// ProxyCache is the response-cache policy for whichever proxy form owns
	// location / (slice 25). Nil means no cache. The proxy_cache_path zone it
	// names lives in a panel-owned http-level table file written in the same
	// transaction, and the cached bytes live under the Manager's CacheDir.
	ProxyCache *ProxyCache `json:"proxy_cache,omitempty"`
	// RedirectTarget is the validated absolute URL when the site redirects
	// every request. Redirect, proxy and rewrite all own `location /`, so at
	// most one of them may be set. RedirectPaths adds exact path exceptions;
	// those use their own `location =` blocks and therefore do not own `/`.
	RedirectTarget   string         `json:"redirect_target,omitempty"`
	RedirectCode     int            `json:"redirect_code,omitempty"`
	RedirectKeepPath bool           `json:"redirect_keep_path,omitempty"`
	RedirectPaths    []RedirectRule `json:"redirect_paths,omitempty"`
	// ErrorPages maps HTTP error statuses to URIs under the site root. The
	// server-level error_page directives own no location, so the table
	// coexists with every other feature.
	ErrorPages []ErrorPageRule `json:"error_pages,omitempty"`
	// Hotlink guards static assets with a fixed Referer check. It owns a regex
	// location for asset extensions rather than `location /`, so it can coexist
	// with rewrite templates but not with a proxy or redirect that would make
	// the local asset block unreachable.
	Hotlink           bool `json:"hotlink,omitempty"`
	HotlinkAllowEmpty bool `json:"hotlink_allow_empty,omitempty"`
	// AutoIndex turns on nginx's server-level directory listing. It only changes
	// what happens to a request that resolves to a directory with no default
	// document; it never disables the index or the location handlers.
	AutoIndex bool `json:"autoindex,omitempty"`
	// AuthUser is the Basic Auth username when the whole vhost is protected.
	// AuthFile is the panel-owned password file for this site; it is derived
	// from AuthDir on every read and never stored in the marker, because the
	// directory is host state rather than a property of the site.
	AuthUser string `json:"auth_user,omitempty"`
	AuthFile string `json:"-"`
	// LogDir is the directory this site's access/error logs live in. Like
	// AuthFile it is host state derived from the Manager on every read, never
	// stored in the marker: a tampered marker cannot move where logs are read.
	LogDir string `json:"-"`
	// RealIPFrom lists the proxy addresses or CIDRs whose forwarding header is
	// trusted; RealIPHeader names that header. Both are empty when the site uses
	// the peer address directly. The list is explicit because trusting every
	// peer would let any client forge the address in the access log.
	RealIPFrom   []string `json:"real_ip_from,omitempty"`
	RealIPHeader string   `json:"real_ip_header,omitempty"`
	// Limits is the site's traffic ceiling, nil when the site is not limited.
	// The shared memory zones it names are defined in a separate panel-owned
	// file at http level, written in the same transaction as this vhost.
	Limits *TrafficLimit `json:"limits,omitempty"`
	// Cors is the site's cross-origin policy, nil when CORS is off. It renders
	// fixed server-level add_header directives plus an OPTIONS short-circuit
	// and does not own `location /`, so it coexists with every other feature.
	Cors *CorsSettings `json:"cors,omitempty"`
	// PHPVersion and PHPSocket name the fpm backend this site's .php location
	// points at. The socket is supplied by the platform layer, which derives it
	// from a discovered installation; it is never taken from an HTTP request.
	PHPVersion string `json:"php_version,omitempty"`
	PHPSocket  string `json:"php_socket,omitempty"`
}

// Spec is the create request after decoding. PHPVersion/PHPSocket are filled by
// the platform layer after it has checked that the version really has fpm.
type Spec struct {
	Name       string   `json:"name"`
	Domains    []string `json:"domains"`
	Root       string   `json:"root"`
	Index      []string `json:"index,omitempty"`
	Rewrite    string   `json:"rewrite,omitempty"`
	PHPVersion string   `json:"php_version,omitempty"`
	PHPSocket  string   `json:"php_socket,omitempty"`
}

type markerPayload struct {
	Name              string          `json:"name"`
	Domains           []string        `json:"domains"`
	Root              string          `json:"root"`
	CreatedAt         string          `json:"created_at"`
	Index             []string        `json:"index,omitempty"`
	Rewrite           string          `json:"rewrite,omitempty"`
	ProxyTarget       string          `json:"proxy_target,omitempty"`
	ProxyWebSocket    bool            `json:"proxy_websocket,omitempty"`
	ProxyUpstreams    []ProxyUpstream `json:"proxy_upstreams,omitempty"`
	ProxyLBMethod     string          `json:"proxy_lb_method,omitempty"`
	ProxyCache        *ProxyCache     `json:"proxy_cache,omitempty"`
	RedirectTarget    string          `json:"redirect_target,omitempty"`
	RedirectCode      int             `json:"redirect_code,omitempty"`
	RedirectKeepPath  bool            `json:"redirect_keep_path,omitempty"`
	RedirectPaths     []RedirectRule  `json:"redirect_paths,omitempty"`
	ErrorPages        []ErrorPageRule `json:"error_pages,omitempty"`
	Limits            *TrafficLimit   `json:"limits,omitempty"`
	Cors              *CorsSettings   `json:"cors,omitempty"`
	Hotlink           bool            `json:"hotlink,omitempty"`
	HotlinkAllowEmpty bool            `json:"hotlink_allow_empty,omitempty"`
	AutoIndex         bool            `json:"autoindex,omitempty"`
	AuthUser          string          `json:"auth_user,omitempty"`
	RealIPFrom        []string        `json:"real_ip_from,omitempty"`
	RealIPHeader      string          `json:"real_ip_header,omitempty"`
	TLS               *markerTLS      `json:"tls,omitempty"`
	PHPVersion        string          `json:"php_version,omitempty"`
	PHPSocket         string          `json:"php_socket,omitempty"`
}

var (
	nameRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	domainRe  = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	rootRe    = regexp.MustCompile(`^/[A-Za-z0-9._\-/]+$`)
	indexRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	phpVerRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	phpSockRe = regexp.MustCompile(`^/[A-Za-z0-9._\-/]+\.sock$`)
)

// validateIndex checks the custom document-index list. Entries become tokens in
// an nginx directive, so paths, whitespace, semicolons and braces are rejected
// by shape rather than escaped. A .php file is refused while the site is static
// because nginx would serve it as text: selecting index.php without a PHP
// handler is a source-code leak, not a routing preference.
func validateIndex(index []string, phpBound bool) error {
	if len(index) > 10 {
		return fmt.Errorf("%w：默认文档最多 10 项", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, name := range index {
		if !indexRe.MatchString(name) || strings.Contains(name, "..") {
			return fmt.Errorf("%w：默认文档 %q 必须是文件名（字母、数字、点、下划线、连字符），不能包含路径", ErrInvalid, name)
		}
		if seen[name] {
			return fmt.Errorf("%w：默认文档 %q 重复", ErrInvalid, name)
		}
		seen[name] = true
		lower := strings.ToLower(name)
		if !phpBound && (strings.Contains(lower, ".php") || strings.HasSuffix(lower, ".phtml") ||
			strings.HasSuffix(lower, ".phar")) {
			return fmt.Errorf("%w：默认文档 %q 是 PHP 源文件，但站点未绑定 PHP；nginx 会把它当普通文本返回", ErrInvalid, name)
		}
	}
	return nil
}

func normalizeIndex(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

// normalizeDomains lowercases, validates and de-duplicates a server_name list.
// It is shared by Create and SetBasics so both write paths accept exactly the
// same hostnames.
func normalizeDomains(in []string) ([]string, error) {
	if len(in) == 0 || len(in) > 20 {
		return nil, fmt.Errorf("%w：需要 1-20 个域名", ErrInvalid)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if err := ValidateDomain(d); err != nil {
			return nil, err
		}
		if seen[d] {
			return nil, fmt.Errorf("%w：域名 %q 重复", ErrInvalid, d)
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// validatePHP accepts either "no PHP binding" (both fields empty) or a version
// plus the absolute unix socket the platform resolved for it. The socket is
// rendered into nginx config, so whitespace, semicolons, braces and `..` are
// rejected rather than escaped: a config injection here would be root-owned
// nginx configuration, not a cosmetic problem.
func validatePHP(version, socket string) error {
	version = strings.TrimSpace(version)
	socket = strings.TrimSpace(socket)
	if version == "" && socket == "" {
		return nil
	}
	if version == "" || socket == "" {
		return fmt.Errorf("%w：PHP 版本与 socket 必须同时给出", ErrInvalid)
	}
	if !phpVerRe.MatchString(version) {
		return fmt.Errorf("%w：PHP 版本 %q 需要形如 8.3", ErrInvalid, version)
	}
	if !phpSockRe.MatchString(socket) || strings.Contains(socket, "..") {
		return fmt.Errorf("%w：PHP socket %q 需要是绝对路径且以 .sock 结尾", ErrInvalid, socket)
	}
	return nil
}

// ValidateName is also used by the API before touching the filesystem, so the
// answer is the same whether or not a Manager exists.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%w：站点名用 2-32 位小写字母、数字或连字符，且以字母开头", ErrInvalid)
	}
	return nil
}

// ValidateDomain accepts a hostname or a single leading wildcard, never a
// scheme, port or path: nginx's server_name is not a URL.
func ValidateDomain(d string) error {
	if len(d) > 253 || !domainRe.MatchString(strings.ToLower(d)) {
		return fmt.Errorf("%w：域名 %q 需要是 example.com 或 *.example.com 的形状", ErrInvalid, d)
	}
	return nil
}

// ValidateRoot requires an absolute path below the panel's site root. The
// confinement is deliberate: a "root" field that can point anywhere turns a
// site-creation form into a file-read primitive over the whole disk.
func (m *Manager) ValidateRoot(root string) error {
	if root == "" {
		return fmt.Errorf("%w：站点根目录为空", ErrInvalid)
	}
	if !rootRe.MatchString(root) || strings.Contains(root, "..") {
		return fmt.Errorf("%w：站点根目录只允许绝对路径与字母数字、点、下划线、连字符", ErrInvalid)
	}
	clean := filepath.Clean(root)
	base := filepath.Clean(m.SiteRoot)
	if clean != base && !strings.HasPrefix(clean, base+string(os.PathSeparator)) {
		return fmt.Errorf("%w：站点根目录必须位于 %s 之下", ErrInvalid, m.SiteRoot)
	}
	return nil
}

// List returns only files the panel wrote. Anything else in the directory is
// somebody else's configuration and is not the panel's to report or touch.
func (m *Manager) List() ([]Site, error) {
	ents, err := os.ReadDir(m.Layout.Dir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Site{}, nil
		}
		return nil, err
	}
	out := []Site{}
	seen := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), filePrefix) || !strings.HasSuffix(e.Name(), fileSuffix) {
			continue
		}
		s, ok := m.readSite(e.Name())
		if !ok {
			continue // foreign file that happens to match the pattern
		}
		seen[e.Name()] = true
		out = append(out, s)
	}
	// In conf.d mode a stopped site lives in the parking directory outside
	// every include; it is still the panel's site and must stay listed.
	if dd := m.Layout.DisabledDir(); dd != "" {
		if parked, err := os.ReadDir(dd); err == nil {
			for _, e := range parked {
				if e.IsDir() || seen[e.Name()] || !strings.HasPrefix(e.Name(), filePrefix) || !strings.HasSuffix(e.Name(), fileSuffix) {
					continue
				}
				s, ok := m.readSite(e.Name())
				if !ok {
					continue
				}
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// readSite parses one panel-owned file. ok=false means the file exists but is
// not ours (no marker) or cannot be parsed; either way it is not listed.
func (m *Manager) readSite(filename string) (Site, bool) {
	p := filepath.Join(m.Layout.Dir(), filename)
	b, err := os.ReadFile(p)
	parked := false
	if err != nil && m.Layout.Mode == ModeConfD {
		// A stopped conf.d site is parked outside the include; every feature
		// write keeps addressing it there until it is enabled again.
		p = m.disabledPath(filename)
		b, err = os.ReadFile(p)
		parked = err == nil
	}
	if err != nil {
		return Site{}, false
	}
	payload, ok := parseMarker(string(b))
	if !ok {
		return Site{}, false
	}
	// The filename must agree with the marker. A mismatch means the file was
	// copied or renamed by hand; treating it as ours would let a rename trick
	// the delete path into removing the wrong site.
	if FileName(payload.Name) != filename {
		return Site{}, false
	}
	s := Site{
		Name: payload.Name, Domains: payload.Domains, Root: payload.Root,
		ConfigPath: p, CreatedAt: payload.CreatedAt, Index: payload.Index,
		Rewrite: payload.Rewrite, ProxyTarget: payload.ProxyTarget, ProxyWebSocket: payload.ProxyWebSocket,
		ProxyUpstreams: payload.ProxyUpstreams, ProxyLBMethod: payload.ProxyLBMethod,
		ProxyCache:     payload.ProxyCache,
		RedirectTarget: payload.RedirectTarget, RedirectCode: payload.RedirectCode,
		RedirectKeepPath: payload.RedirectKeepPath, RedirectPaths: payload.RedirectPaths,
		ErrorPages: payload.ErrorPages,
		Hotlink:    payload.Hotlink, HotlinkAllowEmpty: payload.HotlinkAllowEmpty,
		AutoIndex: payload.AutoIndex,
		AuthUser:  payload.AuthUser, AuthFile: authPath(m.AuthDir, payload.Name),
		LogDir:     m.LogDir,
		RealIPFrom: payload.RealIPFrom, RealIPHeader: payload.RealIPHeader,
		PHPVersion: payload.PHPVersion, PHPSocket: payload.PHPSocket,
	}
	s.Limits = limitsFromMarker(payload)
	s.Cors = corsFromMarker(payload)
	s.TLS = m.tlsFromMarker(payload)
	if lp := m.Layout.LinkPath(payload.Name); lp != "" {
		if fi, err := os.Lstat(lp); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			s.Enabled = true
		}
	} else {
		s.Enabled = !parked
	}
	return s, true
}

func parseMarker(body string) (markerPayload, bool) {
	var p markerPayload
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, markerLine) {
			continue
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, markerLine)), &p); err != nil {
			return markerPayload{}, false
		}
		if validatePHP(p.PHPVersion, p.PHPSocket) != nil {
			return markerPayload{}, false
		}
		if validateIndex(p.Index, p.PHPVersion != "") != nil {
			return markerPayload{}, false
		}
		if validateRewrite(p.Rewrite, p.PHPVersion != "") != nil {
			return markerPayload{}, false
		}
		ups, err := normalizeProxyUpstreams(p.ProxyUpstreams)
		if err != nil {
			return markerPayload{}, false
		}
		lbMethod, err := normalizeProxyLBMethod(p.ProxyLBMethod)
		if err != nil {
			return markerPayload{}, false
		}
		if len(ups) == 0 {
			lbMethod = ""
		}
		// WebSocket needs a proxy owner; with upstreams the owner is the
		// upstream block, so normalizeProxy must not demand a single target.
		target, ws, err := normalizeProxy(p.ProxyTarget, p.ProxyWebSocket && len(ups) == 0)
		if err != nil {
			return markerPayload{}, false
		}
		if len(ups) > 0 {
			if target != "" {
				return markerPayload{}, false
			}
			ws = p.ProxyWebSocket
		}
		p.ProxyTarget, p.ProxyWebSocket = target, ws
		p.ProxyUpstreams, p.ProxyLBMethod = ups, lbMethod
		cache, err := normalizeProxyCache(p.ProxyCache)
		if err != nil {
			return markerPayload{}, false
		}
		if cache != nil && target == "" && len(ups) == 0 {
			// A cache without a proxy owner would render proxy_cache directives
			// into a static location; the file is not ours to serve.
			return markerPayload{}, false
		}
		p.ProxyCache = cache
		redirect, code, keepPath, err := normalizeRedirect(p.RedirectTarget, p.RedirectCode, p.RedirectKeepPath)
		if err != nil {
			return markerPayload{}, false
		}
		p.RedirectTarget, p.RedirectCode, p.RedirectKeepPath = redirect, code, keepPath
		pathRules, err := normalizeRedirectPaths(p.RedirectPaths)
		if err != nil {
			return markerPayload{}, false
		}
		p.RedirectPaths = pathRules
		errorPages, err := normalizeErrorPages(p.ErrorPages)
		if err != nil {
			return markerPayload{}, false
		}
		p.ErrorPages = errorPages
		if err := errorPagesCollide(p.ErrorPages, p.RedirectPaths); err != nil {
			return markerPayload{}, false
		}
		if p.Cors != nil {
			cors, err := normalizeCors(*p.Cors)
			if err != nil {
				return markerPayload{}, false
			}
			if len(cors.Origins) == 0 {
				p.Cors = nil
			} else {
				p.Cors = &cors
			}
		}
		if p.Limits != nil {
			limit, err := normalizeTrafficLimit(*p.Limits)
			if err != nil {
				return markerPayload{}, false
			}
			if !limit.active() {
				p.Limits = nil
			} else if !limitZoneRe.MatchString(limitZoneName(p.Name)) {
				// A zone name that cannot be rendered safely makes the whole
				// file foreign rather than letting it reach the http context.
				return markerPayload{}, false
			} else {
				p.Limits = &limit
			}
		}
		if !p.Hotlink {
			p.HotlinkAllowEmpty = false
		}
		if p.AuthUser != "" && !authUserRe.MatchString(p.AuthUser) {
			return markerPayload{}, false
		}
		from, header, err := normalizeRealIP(p.RealIPFrom, p.RealIPHeader)
		if err != nil {
			return markerPayload{}, false
		}
		p.RealIPFrom, p.RealIPHeader = from, header
		if p.Hotlink && (target != "" || len(ups) > 0 || redirect != "") {
			return markerPayload{}, false
		}
		owners := 0
		if target != "" || len(ups) > 0 {
			owners++
		}
		if redirect != "" {
			owners++
		}
		if normalizeRewrite(p.Rewrite) != "none" {
			owners++
		}
		if owners > 1 {
			return markerPayload{}, false
		}
		return p, p.Name != "" && len(p.Domains) > 0 && p.Root != ""
	}
	return markerPayload{}, false
}

// Create writes a static site and reloads nginx only after `nginx -t` passes.
// On any failure the previous state is restored exactly.
func (m *Manager) Create(spec Spec) (Site, error) {
	if err := ValidateName(spec.Name); err != nil {
		return Site{}, err
	}
	domains, err := normalizeDomains(spec.Domains)
	if err != nil {
		return Site{}, err
	}
	root := spec.Root
	if root == "" {
		root = filepath.Join(m.SiteRoot, spec.Name)
	}
	if err := m.ValidateRoot(root); err != nil {
		return Site{}, err
	}
	root = filepath.Clean(root)
	index := normalizeIndex(spec.Index)
	rewrite := normalizeRewrite(spec.Rewrite)
	phpVersion := strings.TrimSpace(spec.PHPVersion)
	phpSocket := strings.TrimSpace(spec.PHPSocket)
	if err := validatePHP(phpVersion, phpSocket); err != nil {
		return Site{}, err
	}
	if err := validateIndex(index, phpVersion != ""); err != nil {
		return Site{}, err
	}
	if err := validateRewrite(rewrite, phpVersion != ""); err != nil {
		return Site{}, err
	}

	confPath := m.Layout.ConfigPath(spec.Name)
	if _, err := os.Lstat(confPath); err == nil {
		return Site{}, ErrExists
	}
	if lp := m.Layout.LinkPath(spec.Name); lp != "" {
		if _, err := os.Lstat(lp); err == nil {
			return Site{}, ErrExists
		}
	}
	// A stopped conf.d site still owns its name; creating over the parked
	// file would silently destroy the stopped site's configuration.
	if m.Layout.Mode == ModeConfD {
		if _, err := os.Lstat(m.disabledPath(FileName(spec.Name))); err == nil {
			return Site{}, ErrExists
		}
	}

	createdAt := m.now().UTC().Format(time.RFC3339)
	site := Site{
		Name: spec.Name, Domains: domains, Root: root, Index: index,
		ConfigPath: confPath, Enabled: true, CreatedAt: createdAt,
		Rewrite: rewrite, PHPVersion: phpVersion, PHPSocket: phpSocket,
		LogDir: m.LogDir,
	}

	// The document root is operator data, but creating it is part of creating
	// the site. Track whether we made it so a rollback does not delete a
	// directory that was already there.
	_, statErr := os.Stat(root)
	madeRoot := errors.Is(statErr, os.ErrNotExist)
	if madeRoot {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return Site{}, fmt.Errorf("创建站点目录: %w", err)
		}
	}
	if err := os.MkdirAll(m.Layout.Dir(), 0o755); err != nil {
		m.undoRoot(root, madeRoot)
		return Site{}, fmt.Errorf("创建配置目录: %w", err)
	}
	if err := m.ensureLogDir(); err != nil {
		m.undoRoot(root, madeRoot)
		return Site{}, err
	}
	// Create writes the vhost directly (not through applyFiles), so it takes
	// its own pre-write snapshot — normally recording "the file was absent".
	if err := m.snapshotHistory(confPath); err != nil {
		m.undoRoot(root, madeRoot)
		return Site{}, err
	}

	var prev []byte
	existed := false
	if b, err := os.ReadFile(confPath); err == nil {
		prev, existed = b, true
	}

	body := render(site)
	tmp := confPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		m.undoRoot(root, madeRoot)
		return Site{}, fmt.Errorf("写入站点配置: %w", err)
	}
	if err := os.Rename(tmp, confPath); err != nil {
		_ = os.Remove(tmp)
		m.undoRoot(root, madeRoot)
		return Site{}, fmt.Errorf("落盘站点配置: %w", err)
	}
	linkMade := false
	if lp := m.Layout.LinkPath(spec.Name); lp != "" {
		target, err := filepath.Rel(m.Layout.Enabled, confPath)
		if err != nil {
			target = confPath
		}
		if err := os.Symlink(target, lp); err != nil {
			m.rollbackCreate(confPath, "", prev, existed)
			m.undoRoot(root, madeRoot)
			return Site{}, fmt.Errorf("启用站点: %w", err)
		}
		linkMade = true
	}

	if out, err := m.TestConfig(); err != nil {
		m.rollbackCreate(confPath, m.Layout.LinkPath(spec.Name), prev, existed)
		if linkMade {
			_ = os.Remove(m.Layout.LinkPath(spec.Name))
		}
		m.undoRoot(root, madeRoot)
		return Site{}, fmt.Errorf("%w：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		m.rollbackCreate(confPath, m.Layout.LinkPath(spec.Name), prev, existed)
		if linkMade {
			_ = os.Remove(m.Layout.LinkPath(spec.Name))
		}
		m.undoRoot(root, madeRoot)
		return Site{}, fmt.Errorf("%w：reload 失败：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	return site, nil
}

// SetPHP binds (or, with an empty version, unbinds) the site's .php handler.
// The platform layer resolves version→socket before calling; this method only
// validates the shape and writes through the same test-before-reload protocol
// as every other config change, so a failed switch leaves the previous backend
// in place.
func (m *Manager) SetPHP(name, version, socket string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	version = strings.TrimSpace(version)
	socket = strings.TrimSpace(socket)
	if err := validatePHP(version, socket); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if err := validateIndex(site.Index, version != ""); err != nil {
		return Site{}, err
	}
	// A PHP-dependent rewrite template cannot survive a switch back to static:
	// its fallback target is index.php, which nginx would then serve as text.
	if err := validateRewrite(site.Rewrite, version != ""); err != nil {
		return Site{}, err
	}
	site.PHPVersion, site.PHPSocket = version, socket
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}

// SetBasics replaces the editable core of a panel-owned site: domains, document
// root and the optional index list. It is a full replacement, not a patch; an
// empty root keeps the current one (a site without a root is not a thing) and
// an empty index means the built-in default list.
//
// Changing domains while HTTPS is on must not silently serve a certificate for
// the old names, so the existing certificate is re-checked against the new list
// before anything is written. Editing the root may create the new directory;
// a rejected config removes it again, exactly like Create's rollback.
func (m *Manager) SetBasics(name string, domains []string, root string, index []string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	domains, err := normalizeDomains(domains)
	if err != nil {
		return Site{}, err
	}
	root = strings.TrimSpace(root)
	if root == "" {
		root = site.Root
	}
	if err := m.ValidateRoot(root); err != nil {
		return Site{}, err
	}
	root = filepath.Clean(root)
	index = normalizeIndex(index)
	if err := validateIndex(index, site.PHPVersion != ""); err != nil {
		return Site{}, err
	}
	if !slices.Equal(domains, site.Domains) && site.TLS != nil {
		certPath, keyPath := m.certPaths(site.Name)
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return Site{}, fmt.Errorf("%w：域名变更需要现有证书可读（%v）；请先关闭 HTTPS 再编辑", ErrTLSInvalid, err)
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return Site{}, fmt.Errorf("%w：域名变更需要现有私钥可读（%v）；请先关闭 HTTPS 再编辑", ErrTLSInvalid, err)
		}
		if _, err := validateCertificate(certPEM, keyPEM, domains, m.now()); err != nil {
			detail := strings.TrimPrefix(err.Error(), ErrTLSInvalid.Error())
			detail = strings.TrimPrefix(detail, "：")
			return Site{}, fmt.Errorf("%w：新域名需要一份覆盖它们的证书（%s）；可先关闭 HTTPS，编辑后重新签发或上传", ErrTLSInvalid, detail)
		}
	}

	madeRoot := false
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return Site{}, fmt.Errorf("创建站点目录: %w", err)
		}
		madeRoot = true
	}
	site.Domains, site.Root, site.Index = domains, root, index
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		m.undoRoot(root, madeRoot)
		return Site{}, err
	}
	return site, nil
}

// applyConfig is the single write path for an existing site: snapshot, write,
// test, reload, and restore the exact previous bytes on either failure. It
// deliberately reports "no change" as success without a reload.
func (m *Manager) applyConfig(path, want string) error {
	return m.applyFiles([]configFile{{Path: path, Body: &want}})
}

// configFile is one file inside a single test-before-reload transaction. Body
// of nil, or of empty string, means the file must not be there afterwards —
// which is how a panel-owned file disappears without ever leaving an empty
// config behind. OwnedCheck guards files whose name the panel chose but whose
// current bytes it did not write: the check runs before anything is touched,
// so a foreign file is refused rather than replaced.
type configFile struct {
	Path       string
	Body       *string
	OwnedCheck func(string) bool
}

// fileSnapshot is what rollback needs for one file: its exact previous bytes,
// and whether it existed at all.
type fileSnapshot struct {
	path    string
	prev    []byte
	existed bool
}

// rollbackCreate restores the exact pre-create state: previous bytes when the
// file already existed (it should not, but a race is not a reason to delete
// somebody's file), nothing when it did not.
func (m *Manager) rollbackCreate(confPath, linkPath string, prev []byte, existed bool) {
	_ = os.Remove(confPath)
	if linkPath != "" {
		_ = os.Remove(linkPath)
	}
	if existed {
		_ = os.WriteFile(confPath, prev, 0o644)
	}
}

func (m *Manager) undoRoot(root string, made bool) {
	if !made {
		return
	}
	_ = os.Remove(root) // only removes an empty directory
}

// Delete removes one panel-owned site. The config file is kept in memory until
// both `nginx -t` and the reload succeed; a failed reload therefore leaves the
// site exactly as it was.
func (m *Manager) Delete(name string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	filename := FileName(name)
	site, ok := m.readSite(filename)
	if !ok {
		return Site{}, ErrNotFound
	}
	// site.ConfigPath, not Layout.ConfigPath: a stopped conf.d site lives in
	// the parking directory, and deleting it must remove the parked file.
	confPath := site.ConfigPath
	linkPath := m.Layout.LinkPath(name)
	linkTarget := ""
	if linkPath != "" {
		if t, err := os.Readlink(linkPath); err == nil {
			linkTarget = t
		}
	}
	// The enabled symlink must go BEFORE the transaction: the wildcard
	// include still lists it, and nginx -t follows it to the deleted vhost
	// (open() ENOENT), which would fail every delete on a sites-enabled
	// layout. On failure the link is restored together with the file bytes.
	if linkPath != "" {
		if err := os.Remove(linkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Site{}, err
		}
	}
	restoreLink := func() {
		if linkPath != "" && linkTarget != "" {
			_ = os.Symlink(linkTarget, linkPath)
		}
	}

	// The zone table is rebuilt from the remaining sites as part of the same
	// transaction, so deleting the last limited site cannot leave a vhost
	// naming a zone that no longer exists — and cannot leave an empty config
	// file in an http-level include either.
	rows, err := m.limitsRows("", nil, name)
	if err != nil {
		restoreLink()
		return Site{}, err
	}
	table := renderLimits(rows)
	files := []configFile{{Path: confPath, Body: nil}}
	if len(rows) > 0 || m.limitsFileExists() {
		tablePath, err := m.limitsPath()
		if err != nil {
			restoreLink()
			return Site{}, err
		}
		files = append(files, configFile{Path: tablePath, Body: &table, OwnedCheck: parseLimitsMarker})
	}
	// The upstream table is rebuilt the same way: deleting the last
	// multi-upstream site must not leave a vhost-less upstream file behind,
	// and deleting any site must not leave its block in the table.
	upRows, err := m.upstreamRows("", nil, "", name)
	if err != nil {
		restoreLink()
		return Site{}, err
	}
	if len(upRows) > 0 || m.upstreamsFileExists() {
		tablePath, err := m.upstreamsPath()
		if err != nil {
			restoreLink()
			return Site{}, err
		}
		upTable := renderUpstreams(upRows)
		files = append(files, configFile{Path: tablePath, Body: &upTable, OwnedCheck: parseUpstreamsMarker})
	}
	// The proxy-cache table follows the same rule: the deleted site's zone row
	// goes in the same transaction, and the last row removes the file.
	cacheRows, err := m.cacheRows("", nil, name)
	if err != nil {
		restoreLink()
		return Site{}, err
	}
	files, err = m.cacheTableFile(cacheRows, files)
	if err != nil {
		restoreLink()
		return Site{}, err
	}
	if err := m.applyFiles(files); err != nil {
		restoreLink()
		return Site{}, err
	}
	// Cached bytes are panel data tied to the deleted vhost; drop them only
	// after the transaction committed.
	m.removeCacheDir(name)
	// The certificate is panel data tied to this site, so it goes with the
	// config. The document root stays; that is operator data.
	if site.TLS != nil {
		m.removeCerts(name)
	}
	// Same for the password file: it is only meaningful to this vhost, and
	// leaving a credential file behind after the gate is gone is pure residue.
	_ = os.Remove(authPath(m.AuthDir, name))
	return site, nil
}

// render produces the server block(s). A site without TLS keeps the exact
// shape the previous slice shipped. A TLS site gets either one block listening
// on 80 and 443 (no redirect) or a redirect block plus a 443-only block, so
// "force HTTPS" is a config fact rather than a checkbox the front end believes.
func render(s Site) string {
	payload, _ := json.Marshal(markerPayload{
		Name: s.Name, Domains: s.Domains, Root: s.Root, CreatedAt: s.CreatedAt,
		Index:             s.Index,
		Rewrite:           s.Rewrite,
		ProxyTarget:       s.ProxyTarget,
		ProxyWebSocket:    s.ProxyWebSocket,
		ProxyUpstreams:    s.ProxyUpstreams,
		ProxyLBMethod:     s.ProxyLBMethod,
		ProxyCache:        s.ProxyCache,
		RedirectTarget:    s.RedirectTarget,
		RedirectCode:      s.RedirectCode,
		RedirectKeepPath:  s.RedirectKeepPath,
		RedirectPaths:     s.RedirectPaths,
		ErrorPages:        s.ErrorPages,
		Limits:            s.Limits,
		Cors:              s.Cors,
		Hotlink:           s.Hotlink,
		HotlinkAllowEmpty: s.HotlinkAllowEmpty,
		AutoIndex:         s.AutoIndex,
		AuthUser:          s.AuthUser,
		RealIPFrom:        s.RealIPFrom,
		RealIPHeader:      s.RealIPHeader,
		TLS:               markerFromTLS(s.Name, s.TLS),
		PHPVersion:        s.PHPVersion, PHPSocket: s.PHPSocket,
	})
	var b strings.Builder
	b.WriteString(headerLine + "\n")
	b.WriteString(markerLine + string(payload) + "\n")
	tlsOn := s.TLS != nil && s.TLS.Enabled
	if tlsOn && s.TLS.Redirect {
		b.WriteString(renderRedirect(s))
		b.WriteString("\n")
	}
	b.WriteString(renderServer(s, tlsOn))
	return b.String()
}

// TestConfig runs `nginx -t`. It is exported because the platform layer's
// WebServerCtl needs it, and because the API never reloads without it.
func (m *Manager) TestConfig() ([]byte, error) {
	return m.run("nginx", "-t")
}

// Reload asks the running nginx to re-read its configuration (SIGHUP).
func (m *Manager) Reload() ([]byte, error) {
	return m.run("nginx", "-s", "reload")
}

// Restart is the fallback for hosts where reload has no running master to
// signal.
func (m *Manager) Restart() ([]byte, error) {
	return m.run("systemctl", "restart", "nginx")
}

func (m *Manager) run(name string, args ...string) ([]byte, error) {
	r := m.Run
	if r == nil {
		r = ExecRunner
	}
	return r(name, args...)
}

func (m *Manager) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}
