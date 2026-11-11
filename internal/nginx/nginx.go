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
	Run      Runner
	Now      func() time.Time
}

// New detects the layout and returns a usable Manager. siteRoot is the parent
// directory new document roots are created under.
func New(base, siteRoot string) (*Manager, error) {
	l, err := Detect(base)
	if err != nil {
		return nil, err
	}
	if siteRoot == "" {
		siteRoot = "/www/wwwroot"
	}
	return &Manager{Layout: l, SiteRoot: siteRoot, Run: ExecRunner, Now: time.Now}, nil
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
}

// Spec is the create request after decoding.
type Spec struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Root    string   `json:"root"`
}

type markerPayload struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Root      string   `json:"root"`
	CreatedAt string   `json:"created_at"`
}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	rootRe   = regexp.MustCompile(`^/[A-Za-z0-9._\-/]+$`)
)

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
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), filePrefix) || !strings.HasSuffix(e.Name(), fileSuffix) {
			continue
		}
		s, ok := m.readSite(e.Name())
		if !ok {
			continue // foreign file that happens to match the pattern
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// readSite parses one panel-owned file. ok=false means the file exists but is
// not ours (no marker) or cannot be parsed; either way it is not listed.
func (m *Manager) readSite(filename string) (Site, bool) {
	p := filepath.Join(m.Layout.Dir(), filename)
	b, err := os.ReadFile(p)
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
		ConfigPath: p, CreatedAt: payload.CreatedAt,
	}
	if lp := m.Layout.LinkPath(payload.Name); lp != "" {
		if fi, err := os.Lstat(lp); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			s.Enabled = true
		}
	} else {
		s.Enabled = true
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
	if len(spec.Domains) == 0 || len(spec.Domains) > 20 {
		return Site{}, fmt.Errorf("%w：需要 1-20 个域名", ErrInvalid)
	}
	seen := map[string]bool{}
	domains := make([]string, 0, len(spec.Domains))
	for _, d := range spec.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if err := ValidateDomain(d); err != nil {
			return Site{}, err
		}
		if seen[d] {
			return Site{}, fmt.Errorf("%w：域名 %q 重复", ErrInvalid, d)
		}
		seen[d] = true
		domains = append(domains, d)
	}
	root := spec.Root
	if root == "" {
		root = filepath.Join(m.SiteRoot, spec.Name)
	}
	if err := m.ValidateRoot(root); err != nil {
		return Site{}, err
	}
	root = filepath.Clean(root)

	confPath := m.Layout.ConfigPath(spec.Name)
	if _, err := os.Lstat(confPath); err == nil {
		return Site{}, ErrExists
	}
	if lp := m.Layout.LinkPath(spec.Name); lp != "" {
		if _, err := os.Lstat(lp); err == nil {
			return Site{}, ErrExists
		}
	}

	createdAt := m.now().UTC().Format(time.RFC3339)
	site := Site{
		Name: spec.Name, Domains: domains, Root: root,
		ConfigPath: confPath, Enabled: true, CreatedAt: createdAt,
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
	confPath := m.Layout.ConfigPath(name)
	prev, err := os.ReadFile(confPath)
	if err != nil {
		return Site{}, fmt.Errorf("读取站点配置: %w", err)
	}
	linkPath := m.Layout.LinkPath(name)
	linkTarget := ""
	if linkPath != "" {
		if t, err := os.Readlink(linkPath); err == nil {
			linkTarget = t
		}
	}

	if err := os.Remove(confPath); err != nil {
		return Site{}, fmt.Errorf("删除站点配置: %w", err)
	}
	if linkPath != "" {
		_ = os.Remove(linkPath)
	}
	restore := func() {
		_ = os.MkdirAll(filepath.Dir(confPath), 0o755)
		_ = os.WriteFile(confPath, prev, 0o644)
		if linkPath != "" && linkTarget != "" {
			_ = os.Symlink(linkTarget, linkPath)
		}
	}

	if out, err := m.TestConfig(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：reload 失败：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	return site, nil
}

// render produces the server block. Only static sites for now: the PHP
// fastcgi block arrives with the version-binding slice, and inventing one here
// would claim a capability the bitmap still reports as degraded.
func render(s Site) string {
	payload, _ := json.Marshal(markerPayload{
		Name: s.Name, Domains: s.Domains, Root: s.Root, CreatedAt: s.CreatedAt,
	})
	var b strings.Builder
	b.WriteString(headerLine + "\n")
	b.WriteString(markerLine + string(payload) + "\n")
	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString("    server_name " + strings.Join(s.Domains, " ") + ";\n\n")
	b.WriteString("    root " + s.Root + ";\n")
	b.WriteString("    index index.html index.htm;\n\n")
	b.WriteString("    location / {\n")
	b.WriteString("        try_files $uri $uri/ =404;\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
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
