package nginx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// The two log kinds a site has. They are a closed vocabulary: the viewer never
// accepts a path from the caller, only one of these names plus the site name,
// and the file location is derived from the Manager's LogDir exactly the way
// the vhost directives derive it.
const (
	LogKindAccess = "access"
	LogKindError  = "error"
)

// logTailWindow caps how much of a log file one read loads into memory. Logs
// grow without bound; the viewer shows the tail, so reading the last megabyte
// is enough for any allowed line count and keeps a multi-GB access log from
// becoming a multi-GB allocation.
const logTailWindow = 1 << 20

// maxLogLines bounds the lines query parameter.
const maxLogLines = 500

// SiteLog is one read of a site's log tail. Exists=false is a real answer, not
// an error: a freshly migrated vhost has not served a request yet, and the
// page must be able to say so instead of pretending the file is empty.
type SiteLog struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Path      string   `json:"path"`
	Exists    bool     `json:"exists"`
	Size      int64    `json:"size"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}

// siteLogPath is the one place a per-site log file location is derived. The
// vhost directives and the viewer both call it, so what nginx writes and what
// the panel reads can never disagree.
func siteLogPath(logDir, name, kind string) string {
	return filepath.Join(logDir, name+"."+kind+".log")
}

// siteLogLines renders the two fixed per-site log directives. The format is
// nginx's built-in `combined` and the error level is nginx's default; neither
// is caller-controllable.
func siteLogLines(logDir, name string) string {
	return "    access_log " + siteLogPath(logDir, name, LogKindAccess) + " combined;\n" +
		"    error_log " + siteLogPath(logDir, name, LogKindError) + ";\n"
}

// nginxUser reads the `user` directive from the host's own nginx.conf. That
// directive — not a guess — decides which account the workers run as, and the
// log directory must be writable by that account or nginx would accept the
// config and then silently drop every log line. A config without the directive
// uses nginx's compiled-in default, nobody.
func nginxUser(configDir string) string {
	b, err := os.ReadFile(filepath.Join(configDir, "nginx.conf"))
	if err != nil {
		return "nobody"
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "user") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "user"))
		rest = strings.TrimSuffix(rest, ";")
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		return strings.Trim(fields[0], `"'`)
	}
	return "nobody"
}

// ensureLogDir makes the per-site log directory exist and be writable by the
// nginx worker before any vhost naming it is tested or reloaded. `nginx -t`
// does not fail on a missing log directory, so without this step a reload
// could accept the config and then fail to open the logs at runtime.
//
// Ownership is only adjusted when the panel runs as root, which is exactly
// when the site provider is offered at all; a non-root caller cannot chown and
// keeps the directory it created.
func (m *Manager) ensureLogDir() error {
	if err := os.MkdirAll(m.LogDir, 0o755); err != nil {
		return fmt.Errorf("创建站点日志目录: %w", err)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup(nginxUser(m.Layout.ConfigDir))
	if err != nil {
		return fmt.Errorf("解析 nginx 运行用户: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("解析 nginx 运行用户 uid: %w", err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("解析 nginx 运行用户 gid: %w", err)
	}
	if err := os.Chown(m.LogDir, uid, gid); err != nil {
		return fmt.Errorf("设置站点日志目录属主: %w", err)
	}
	return nil
}

// ReadLog returns the tail of one of the site's two log files. The site must
// be panel-owned (readSite refuses a foreign or tampered file), the kind and
// line count are validated, and a missing file is reported as Exists=false
// rather than an error. Only the last logTailWindow bytes are ever read.
func (m *Manager) ReadLog(name, kind string, lines int) (SiteLog, error) {
	if err := ValidateName(name); err != nil {
		return SiteLog{}, err
	}
	if kind != LogKindAccess && kind != LogKindError {
		return SiteLog{}, fmt.Errorf("%w：日志类型只能是 access 或 error", ErrInvalid)
	}
	if lines < 1 || lines > maxLogLines {
		return SiteLog{}, fmt.Errorf("%w：行数必须在 1-%d 之间", ErrInvalid, maxLogLines)
	}
	if _, ok := m.readSite(FileName(name)); !ok {
		return SiteLog{}, ErrNotFound
	}
	path := siteLogPath(m.LogDir, name, kind)
	out := SiteLog{Name: name, Kind: kind, Path: path, Lines: []string{}}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return SiteLog{}, fmt.Errorf("读取日志状态: %w", err)
	}
	out.Exists = true
	out.Size = fi.Size()
	f, err := os.Open(path)
	if err != nil {
		return SiteLog{}, fmt.Errorf("打开日志: %w", err)
	}
	defer f.Close()
	window := fi.Size()
	if window > logTailWindow {
		window = logTailWindow
	}
	buf := make([]byte, window)
	if _, err := f.ReadAt(buf, fi.Size()-window); err != nil && err != io.EOF {
		return SiteLog{}, fmt.Errorf("读取日志: %w", err)
	}
	text := string(buf)
	if fi.Size() > window {
		// The window starts mid-line; drop that partial first line.
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		} else {
			text = ""
		}
		out.Truncated = true
	}
	all := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		all = nil
	}
	if len(all) > lines {
		out.Truncated = true
		all = all[len(all)-lines:]
	}
	if all == nil {
		all = []string{}
	}
	out.Lines = all
	return out, nil
}

// MigrateSiteLogs re-renders every panel-owned vhost in one test-before-reload
// transaction so sites created before per-site logs existed gain the two
// directives. Foreign files are never touched: List only returns files whose
// marker parses, and applyFiles refuses anything it did not write. When every
// vhost already matches, applyFiles reports no change and nothing is reloaded.
func (m *Manager) MigrateSiteLogs() error {
	sites, err := m.List()
	if err != nil {
		return fmt.Errorf("列出站点以迁移日志: %w", err)
	}
	files := make([]configFile, 0, len(sites))
	for _, s := range sites {
		body := render(s)
		files = append(files, configFile{Path: s.ConfigPath, Body: &body})
	}
	if len(files) == 0 {
		return nil
	}
	return m.applyFiles(files)
}
