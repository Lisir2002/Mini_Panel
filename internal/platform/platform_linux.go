//go:build linux

package platform

import (
	"bufio"
	"os"
	"strings"
)

type linuxPlatform struct{}

func newPlatform() Platform { return linuxPlatform{} }

func (linuxPlatform) ID() string { return "linux" }

func (linuxPlatform) ConfigDir() string  { return rooted("/etc/minipanel") }
func (linuxPlatform) DataDir() string    { return rooted("/var/lib/minipanel") }
func (linuxPlatform) LogDir() string     { return rooted("/var/log/minipanel") }
func (linuxPlatform) SiteRoot() string   { return envOr("MINI_PANEL_SITE_ROOT", "/www/wwwroot") }
func (linuxPlatform) BackupRoot() string { return envOr("MINI_PANEL_BACKUP_ROOT", "/www/backup") }

// rooted lets a developer relocate the whole footprint with MINI_PANEL_ROOT,
// which is how the unit tests and this repo's demo run avoid touching /etc.
func rooted(p string) string {
	if r := os.Getenv("MINI_PANEL_ROOT"); r != "" {
		return strings.TrimRight(r, "/") + p
	}
	return p
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (linuxPlatform) Detect() (*Capabilities, error) {
	c := newBase()
	c.OSFamily = osFamily()
	c.OSVersion = osVersion(c.OSFamily)
	c.IsPrivileged = os.Geteuid() == 0
	c.Hostname = hostname()

	// Permissions and PHPExtInstall describe the mechanism the host offers; they
	// are facts. The matching *features* stay denied until the code that would
	// use them ships, because "chmod exists" is not the same as "this panel can
	// manage file permissions", and "phpize is installed" is not "extension
	// install works". Reporting the mechanism as the feature is how a UI ends up
	// with a clickable button over an empty handler.
	c.Permissions = "posix"

	c.ReloadMode = ReloadSIGHup
	c.PHPModes = append(c.PHPModes, PHPModeFPM)
	c.PHPExtInstall = append(c.PHPExtInstall, ExtFromPackage, ExtFromSource)
	c.Deny(FeatPHP, "PHP 版本探测与 pool 管理在 M2 交付")

	if have("nginx") != "" || have("openresty") != "" {
		c.WebServers = append(c.WebServers, WebNginx)
		if have("openresty") != "" {
			c.WebServers = append(c.WebServers, WebOpenResty)
		}
	}
	if have("apachectl") != "" || have("httpd") != "" {
		c.WebServers = append(c.WebServers, WebApache)
	}

	switch {
	case have("ufw") != "":
		c.Firewall = FirewallUFW
	case have("firewall-cmd") != "":
		c.Firewall = FirewallFirewalld
	case have("nft") != "":
		c.Firewall = FirewallNftables
	}
	// Both branches deny, for different reasons: the UI must be able to tell
	// "no firewall software on this host" apart from "firewall present, write
	// provider not shipped yet".
	if c.Firewall == FirewallNone {
		c.Deny(FeatFirewall, "未检测到 ufw / firewall-cmd / nft 任一后端，本机没有可管理的防火墙")
	} else {
		c.Deny(FeatFirewall, "当前版本只读展示后端状态；规则写入 Provider 在 M4 交付")
	}

	if have("systemctl") != "" && dirExists("/run/systemd/system") {
		c.ServiceManager = "systemd"
	}
	switch {
	case have("apt-get") != "":
		c.PackageManager = "apt"
	case have("dnf") != "":
		c.PackageManager = "dnf"
	case have("yum") != "":
		c.PackageManager = "yum"
	case have("zypper") != "":
		c.PackageManager = "zypper"
	}
	if have("crontab") != "" {
		c.Schedulers = append(c.Schedulers, SchedCrontab)
	}
	c.SupportsSubSecondCron = true

	// Detection is a fact; the page that would manage it is M4 work. Allowing the
	// feature here because sshd happens to exist is precisely how a panel ends up
	// shipping a button with no code behind it.
	if have("sshd") != "" || dirExists("/run/sshd") {
		c.RemoteAccess = append(c.RemoteAccess, AccessSSH)
		c.Deny(FeatSSHManager, "本机已检测到 sshd；SSH 端口/密钥/登录策略管理页在 M4 交付")
	}
	return c, nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// osFamily maps /etc/os-release ID and ID_LIKE onto our small family set. The
// family decides which package backend and PHP repository we will use in M2.
func osFamily() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	id, like := "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			like = v
		}
	}
	for _, tok := range strings.Fields(id + " " + like) {
		switch tok {
		case "ubuntu", "debian", "mint":
			return "debian"
		case "rhel", "fedora", "centos", "almalinux", "rocky":
			return "rhel"
		case "suse", "sles", "opensuse":
			return "suse"
		case "kylin", "uos", "anolis", "alinux":
			return "cn-enterprise"
		}
	}
	if id != "" {
		return id
	}
	return "unknown"
}

func osVersion(family string) string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return family
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return family
}
