//go:build !linux && !windows

package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// Other platforms (macOS, *BSD) are supported for development only: the panel
// starts, serves the API and reports a minimal capability set, but no host
// management provider is implemented or advertised.
type otherPlatform struct{}

func newPlatform() Platform { return otherPlatform{} }

func (otherPlatform) ID() string { return runtime.GOOS }

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func (p otherPlatform) ConfigDir() string { return rooted("etc/minipanel") }
func (p otherPlatform) DataDir() string   { return rooted("var/lib/minipanel") }
func (p otherPlatform) LogDir() string    { return rooted("var/log/minipanel") }
func (p otherPlatform) SiteRoot() string {
	return envOr("MINI_PANEL_SITE_ROOT", filepath.Join(rooted("www"), "wwwroot"))
}
func (p otherPlatform) BackupRoot() string {
	return envOr("MINI_PANEL_BACKUP_ROOT", filepath.Join(rooted("www"), "backup"))
}

func rooted(rel string) string {
	if r := os.Getenv("MINI_PANEL_ROOT"); r != "" {
		return filepath.Join(r, rel)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "MiniPanel", rel)
}

func (otherPlatform) Detect() (*Capabilities, error) {
	c := newBase()
	c.OSVersion = runtime.GOOS + "/" + runtime.GOARCH
	c.Permissions = "posix"
	c.Hostname = hostname()
	// IsPrivileged stays false: on a development-only platform the value would
	// describe the process, not a capability the panel can act on.
	c.Deny(FeatWebSite, "本平台仅用于开发调试，未实现任何主机管理 Provider")
	return c, nil
}
