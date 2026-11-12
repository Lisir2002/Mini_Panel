package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The site enable switch is the twenty-third slice of M2. BaoTa's site list
// has a 停用/启用 toggle; until now the panel only read `enabled` as a fact
// (the sites-enabled symlink) with no way to change it. This slice adds the
// manual switch — the scheduled expiry stop stays refused (功能设计.md).
//
// Two layouts, two mechanisms, one contract:
//   - sites-available/sites-enabled: stop removes the symlink, start recreates
//     it. The vhost file itself never moves, so every other panel write keeps
//     working on a stopped site exactly as before.
//   - conf.d (no symlink layer): stop moves the vhost into a sibling
//     `minipanel-disabled/` directory that no wildcard include lists, start
//     moves it back. The disabled directory is panel-owned by location; the
//     marker inside the file still has to parse for it to be listed.
//
// Every switch goes through nginx -t before reload, and any failure puts the
// link/file back exactly where it was. A switch to the current state is a
// no-op success with zero nginx commands.

// disabledDirName is the conf.d-mode parking directory for stopped sites. It
// sits next to conf.d under the nginx config root, outside every include.
const disabledDirName = "minipanel-disabled"

// DisabledDir is where conf.d-mode stopped vhosts live. Empty in sites mode,
// where stopping is a symlink fact and the file never moves.
func (l Layout) DisabledDir() string {
	if l.Mode != ModeConfD {
		return ""
	}
	return filepath.Join(l.ConfigDir, disabledDirName)
}

// disabledPath is the parking path for one site file in conf.d mode.
func (m *Manager) disabledPath(filename string) string {
	return filepath.Join(m.Layout.DisabledDir(), filename)
}

// SetEnabled stops or starts one panel-owned site. It is idempotent: asking
// for the state the site is already in returns the site with no nginx command
// run. On any test/reload failure the previous on-disk state is restored, so a
// failed switch never leaves a half-stopped site.
func (m *Manager) SetEnabled(name string, enabled bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if site.Enabled == enabled {
		return site, nil
	}
	var err error
	if m.Layout.Mode == ModeSites {
		err = m.setEnabledLink(site, enabled)
	} else {
		err = m.setEnabledMove(site, enabled)
	}
	if err != nil {
		return Site{}, err
	}
	site.Enabled = enabled
	if m.Layout.Mode == ModeConfD {
		// The returned path must say where the file now lives, matching what
		// the next List/readSite will report.
		if enabled {
			site.ConfigPath = m.Layout.ConfigPath(name)
		} else {
			site.ConfigPath = m.disabledPath(FileName(name))
		}
	}
	return site, nil
}

// setEnabledLink is the sites-enabled mechanism: the symlink is the switch.
func (m *Manager) setEnabledLink(site Site, enabled bool) error {
	lp := m.Layout.LinkPath(site.Name)
	if !enabled {
		target, err := os.Readlink(lp)
		if err != nil {
			return fmt.Errorf("读取启用链接: %w", err)
		}
		if err := os.Remove(lp); err != nil {
			return fmt.Errorf("停用站点: %w", err)
		}
		restore := func() { _ = os.Symlink(target, lp) }
		return m.testReloadOr(restore, "停用站点")
	}
	if err := os.MkdirAll(m.Layout.Enabled, 0o755); err != nil {
		return fmt.Errorf("创建启用目录: %w", err)
	}
	target, err := filepath.Rel(m.Layout.Enabled, site.ConfigPath)
	if err != nil {
		target = site.ConfigPath
	}
	if err := os.Symlink(target, lp); err != nil {
		return fmt.Errorf("启用站点: %w", err)
	}
	restore := func() { _ = os.Remove(lp) }
	return m.testReloadOr(restore, "启用站点")
}

// setEnabledMove is the conf.d mechanism: the file's location is the switch.
func (m *Manager) setEnabledMove(site Site, enabled bool) error {
	active := m.Layout.ConfigPath(site.Name)
	parked := m.disabledPath(FileName(site.Name))
	from, to := active, parked
	if enabled {
		from, to = parked, active
	}
	// A move is a write to the serving set: snapshot the bytes before the
	// file leaves its current home, same rule as every config change.
	if err := m.snapshotHistory(from); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("移动站点配置: %w", err)
	}
	restore := func() { _ = os.Rename(to, from) }
	return m.testReloadOr(restore, "切换站点状态")
}

// testReloadOr runs the shared test→reload protocol and calls restore on any
// failure, so the caller's disk change is undone before the error surfaces.
func (m *Manager) testReloadOr(restore func(), action string) error {
	if out, err := m.TestConfig(); err != nil {
		restore()
		return fmt.Errorf("%w：%s后 nginx -t 失败，已还原：%v", ErrConfigRejected, action, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		restore()
		return fmt.Errorf("%w：%s后 reload 失败，已还原：%v", ErrConfigRejected, action, strings.TrimSpace(string(out)))
	}
	return nil
}
