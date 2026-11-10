//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsPlatform struct{}

func newPlatform() Platform { return windowsPlatform{} }

func (windowsPlatform) ID() string { return "windows" }

func programData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}

func (p windowsPlatform) ConfigDir() string  { return filepath.Join(programData(), "MiniPanel", "conf") }
func (p windowsPlatform) DataDir() string    { return filepath.Join(programData(), "MiniPanel", "data") }
func (p windowsPlatform) LogDir() string     { return filepath.Join(programData(), "MiniPanel", "logs") }
func (p windowsPlatform) SiteRoot() string   { return envOr("MINI_PANEL_SITE_ROOT", `C:\wwwroot`) }
func (p windowsPlatform) BackupRoot() string { return envOr("MINI_PANEL_BACKUP_ROOT", `C:\wwwbackup`) }

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

func (windowsPlatform) Detect() (*Capabilities, error) {
	c := newBase()
	c.OSFamily = "windows"
	c.OSVersion = windowsCaption()
	c.IsPrivileged = isElevated()
	c.Hostname = hostname()

	// Windows has no POSIX permission bits: the file panel must present ACLs,
	// and chmod-style controls must not be rendered at all.
	c.Permissions = "acl"
	c.Deny(FeatFilePerms, "Windows 使用 ACL 与继承，POSIX 权限位仅作只读展示")

	// nginx/Windows does not implement the POSIX signal model used for graceful
	// reload; treat restart as the only supported activation path and verify the
	// exact behaviour with a canary test when M2 lands.
	c.ReloadMode = ReloadRestartOnly

	// PHP on Windows ships php.exe / php-cgi.exe only — there is no php-fpm
	// binary in the official builds, so the runtime model is a FastCGI process
	// pool rather than FPM pools.
	c.PHPModes = append(c.PHPModes, PHPModeCGI)
	c.Deny("php_fpm", "Windows 官方 PHP 构建不含 php-fpm，Mini Panel 在 Windows 上使用 php-cgi.exe 的 FastCGI 模式")

	// Extensions cannot be compiled on the target: the toolchain must match the
	// upstream build exactly. We install prebuilt DLLs whose name encodes
	// PHP version × TS/NTS × VC runtime × bitness.
	c.PHPExtInstall = append(c.PHPExtInstall, ExtPrebuiltDLL)
	c.Deny(FeatPHPSourceExt, "Windows 上不支持编译 PHP 扩展，只能安装与 PHP 版本 / TS-NTS / VC 运行库 / 位数完全匹配的预编译 DLL")
	c.Deny(FeatPHP, "PHP 版本探测与 php-cgi 进程池管理在 M2 交付")

	if have("nginx.exe") != "" {
		c.WebServers = append(c.WebServers, WebNginx)
	}

	// Windows Filtering Platform is always present; the netsh-backed provider is
	// M4 work, so the capability stays denied with a reason.
	c.Firewall = FirewallWFP
	c.Deny(FeatFirewall, "Windows 防火墙 Provider 在 M4 交付（当前版本只读展示）")

	c.ServiceManager = "windows_scm"
	if have("winget.exe") != "" {
		c.PackageManager = "winget"
	}
	if have("schtasks.exe") != "" {
		c.Schedulers = append(c.Schedulers, SchedTaskschd)
	}
	// Task Scheduler has no per-second recurrence; second-level tasks can only be
	// run by the panel's own scheduler.
	c.SupportsSubSecondCron = true

	c.RemoteAccess = append(c.RemoteAccess, AccessRDP)
	if dirExists(filepath.Join(os.Getenv("SystemRoot"), "System32", "OpenSSH")) {
		c.RemoteAccess = append(c.RemoteAccess, AccessSSH)
	}
	c.Deny(FeatSSHManager, "远程访问管理页在 M4 交付")
	return c, nil
}

// windowsCaption reads the friendly product name from the registry; failures are
// non-fatal and degrade to "windows".
func windowsCaption() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "windows"
	}
	defer k.Close()
	name, _, err1 := k.GetStringValue("ProductName")
	build, _, err2 := k.GetStringValue("CurrentBuildNumber")
	if err1 != nil {
		return "windows"
	}
	if err2 == nil {
		return strings.TrimSpace(name) + " (build " + build + ")"
	}
	return strings.TrimSpace(name)
}

// isElevated asks the process token directly, which is what the Windows service
// must have to write nginx/PHP config under Program Files and to touch the
// firewall. (A write-probe on an HKLM key would answer a different question.)
func isElevated() bool {
	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer t.Close()
	return t.IsElevated()
}
