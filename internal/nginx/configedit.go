package nginx

import (
	"fmt"
	"os"
	"strings"
)

// The config editor is the twenty-second slice of M2. It is deliberately a
// guarded editor, not a file manager: only panel-owned vhosts can be read or
// written here, and the ownership marker line must survive the edit byte for
// byte. Everything else in the file is the operator's to change — the write
// still goes through the same snapshot → write → nginx -t → reload-or-restore
// transaction as every generated write, so a broken edit never reaches a
// reload. Two boundaries are stated rather than hidden: the marker line is
// immutable here (domains, root and the other panel-managed facts have their
// own endpoints, and letting the marker drift would make the site list lie),
// and the next panel feature write regenerates the whole vhost from the
// marker, which overwrites manual additions.

// maxConfigBytes caps one edited vhost. Panel-generated files are a few KB;
// 64 KiB leaves ample room for manual additions without letting the editor
// become a way to push arbitrary large files through the panel.
const maxConfigBytes = 64 * 1024

// SiteConfig is one read of a panel-owned vhost: the path and the exact bytes
// on disk. Content is never regenerated for the read — the operator sees the
// file nginx actually loaded, including any earlier manual edits.
type SiteConfig struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

// markerLines extracts every ownership marker line from a config body.
func markerLines(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, markerLine) {
			out = append(out, line)
		}
	}
	return out
}

// ReadSiteConfig returns the exact on-disk bytes of one panel-owned vhost.
// Foreign files are not the panel's to show: they are refused with the same
// not-found answer every other site endpoint gives.
func (m *Manager) ReadSiteConfig(name string) (SiteConfig, error) {
	if err := ValidateName(name); err != nil {
		return SiteConfig{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return SiteConfig{}, ErrNotFound
	}
	b, err := os.ReadFile(site.ConfigPath)
	if err != nil {
		return SiteConfig{}, err
	}
	return SiteConfig{Name: name, Path: site.ConfigPath, Content: string(b)}, nil
}

// WriteSiteConfig replaces one panel-owned vhost with operator-edited bytes.
// The edit must keep exactly one ownership marker line, identical to the
// current one, and the file must still parse as a panel site — otherwise the
// write is refused before anything touches disk. A passing edit goes through
// applyConfig: nginx -t first, reload only on success, exact restore on any
// failure.
func (m *Manager) WriteSiteConfig(name, content string) (SiteConfig, error) {
	if err := ValidateName(name); err != nil {
		return SiteConfig{}, err
	}
	if len(content) > maxConfigBytes {
		return SiteConfig{}, fmt.Errorf("%w：配置内容最多 %d 字节", ErrInvalid, maxConfigBytes)
	}
	if strings.ContainsRune(content, 0) {
		return SiteConfig{}, fmt.Errorf("%w：配置内容不能包含 NUL 字符", ErrInvalid)
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return SiteConfig{}, ErrNotFound
	}
	current, err := os.ReadFile(site.ConfigPath)
	if err != nil {
		return SiteConfig{}, err
	}
	wantMarkers := markerLines(content)
	if len(wantMarkers) != 1 {
		return SiteConfig{}, fmt.Errorf("%w：配置必须保留且只保留一行 %s 标记；删掉它面板会失去这个站点的所有权", ErrInvalid, strings.TrimSpace(markerLine))
	}
	curMarkers := markerLines(string(current))
	if len(curMarkers) != 1 || wantMarkers[0] != curMarkers[0] {
		return SiteConfig{}, fmt.Errorf("%w：标记行不能修改。域名、根目录等面板管理的事实请用对应功能页修改，否则站点列表会与真实配置脱节", ErrInvalid)
	}
	if _, ok := parseMarker(content); !ok {
		return SiteConfig{}, fmt.Errorf("%w：配置里的面板标记无法解析", ErrInvalid)
	}
	if err := m.applyConfig(site.ConfigPath, content); err != nil {
		return SiteConfig{}, err
	}
	return SiteConfig{Name: name, Path: site.ConfigPath, Content: content}, nil
}
