package platform

import (
	"os"
	"os/exec"
	"runtime"
)

// Current returns the Platform implementation for the host the binary is
// running on. Selection happens once, at build time, through build tags — the
// core never branches on runtime.GOOS.
func Current() Platform { return newPlatform() }

// newBase returns a capability set with every field populated to a safe,
// conservative default and every feature denied. Platform implementations then
// allow only what they have actually verified on the live host — the bitmap must
// never claim a capability because it "usually exists".
func newBase() *Capabilities {
	c := &Capabilities{
		OS:              runtime.GOOS,
		OSFamily:        "unknown",
		Arch:            runtime.GOARCH,
		WebServers:      []WebServerName{},
		PHPModes:        []PHPRuntimeMode{},
		PHPVersions:     []string{},
		PHPFPMVersions:  []string{},
		PHPExtInstall:   []ExtensionInstallMode{},
		ReloadMode:      ReloadNone,
		Firewall:        FirewallNone,
		Schedulers:      []SchedulerKind{SchedPanel},
		ServiceManager:  "none",
		PackageManager:  "none",
		Permissions:     "none",
		RemoteAccess:    []RemoteAccess{},
		DatabaseEngines: []string{},
		// M0 delivers identity, sessions, the entrance, the capability contract
		// and the audit log — and nothing else. A feature is available here only
		// if this binary actually does the thing when you click it today. The
		// tempting version (ACME "is pure Go", file backup "is portable") is the
		// one that renders a live-looking control over an empty implementation,
		// which is exactly the failure the research pass found in BaoTa and that
		// this project refuses to copy.
		//
		// Everything else is declared by the denial table below — the map starts
		// empty so a key cannot exist as an unexplained `false`, which is what
		// the separate bool map made easy in M0.
		Features: map[string]Feature{},
	}
	// Every denial carries the reason the UI must show. Milestone wording is
	// deliberately concrete: "not implemented" is not an acceptable message.
	denials := []struct{ feat, why string }{
		{FeatWebSite, "站点创建与 Nginx 配置生成在 M2 交付"},
		{featSiteWrite, "站点写入随 Nginx Provider 在 M2 交付"},
		{FeatPHP, "PHP 多版本安装在 M2 交付"},
		{FeatPHPVersionSwitch, "PHP 版本切换需要可写的 nginx 站点 Provider 与 php-fpm 后端"},
		{FeatPHPSourceExt, "PHP 扩展编译安装在 M2 交付"},
		{FeatSSL, "站点证书签发与部署随 Nginx Provider 在 M2 交付；面板自身 HTTPS 见 panel.json 的 tls/cert/key"},
		{FeatBackup, "备份任务与归档管理在 M6 交付"},
		{FeatCron, "计划任务调度器在 M6 交付"},
		{FeatFilePerms, "文件权限（属主/模式）管理随文件管理器在 M4 交付"},
		{FeatDatabase, "数据库 Provider 在 M3 交付"},
		{FeatTerminal, "Web 终端与录像审计在 M4 交付"},
		{FeatMonitor, "监控采集与图表在 M4 交付"},
		{FeatFirewall, "防火墙规则写入在 M4 交付"},
		{featFirewallWrite, "防火墙规则写入在 M4 交付"},
		{featServiceWrite, "服务启停在 M4 交付"},
		{FeatSSHManager, "SSH/RDP 访问管理页在 M4 交付"},
	}
	for _, d := range denials {
		c.Deny(d.feat, d.why)
	}
	// The one module M0 actually finished: writes go through internal/audit and
	// the read side is GET /api/v1/audit. No platform may take this away — the
	// audit log is a property of the panel process, not of the host.
	c.Allow(FeatAudit)
	return c
}

// Milestone-scoped sub-features used by the UI to distinguish "can read" from
// "can write". Kept in one place so handlers and the front end agree on names.
const (
	// featPHPFPM is Windows-only: the official PHP builds ship php-cgi.exe, not
	// php-fpm, so the key exists on the bitmap there and nowhere else. It is
	// declared here rather than as a string literal at the call site because
	// capabilities_test.go asserts every bitmap key is a declared one.
	featPHPFPM        = "php_fpm"
	featSiteWrite     = "site_write"
	featFirewallWrite = "firewall_write"
	featServiceWrite  = "service_write"
)

// have looks up an executable on PATH. Detection is always live: a Linux host
// without ufw installed must not report the ufw backend.
func have(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// Hostname is best-effort and never fatal.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return h
}
