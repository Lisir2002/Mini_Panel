// Package platform isolates every OS-specific fact behind an interface, so that
// internal/core never contains a `runtime.GOOS` branch.
//
// Design rule (docs/技术选型与MVP规格.md §2): the UI renders from the capability
// bitmap below and nothing else. A capability that does not exist on the current
// platform must be reported as absent with a human-readable reason — it must
// never be rendered as a control that silently does nothing.
package platform

// ReloadMode describes how a reconfigured web server takes effect.
//
// It is a fact about the host, not a promise about this build: on Linux the
// value is sighup even in M0, where no web server provider exists yet. The UI
// must therefore present it under "探测到的机制" and never imply that a reload
// can be triggered today — web_servers plus the site/ssl features say that.
type ReloadMode string

const (
	// ReloadSIGHup: graceful reload is available (Linux nginx/apache).
	ReloadSIGHup ReloadMode = "sighup"
	// ReloadRestartOnly: the process must be stopped and started again.
	ReloadRestartOnly ReloadMode = "restart_only"
	// ReloadNone: no web server is managed on this platform/build.
	ReloadNone ReloadMode = "none"
)

// WebServerName identifies a supported front-end server.
type WebServerName string

const (
	WebNginx     WebServerName = "nginx"
	WebOpenResty WebServerName = "openresty"
	WebApache    WebServerName = "apache"
)

// PHPRuntimeMode identifies how PHP is executed.
type PHPRuntimeMode string

const (
	PHPModeFPM      PHPRuntimeMode = "fpm"       // unix only
	PHPModeCGI      PHPRuntimeMode = "cgi"       // FastCGI via php-cgi.exe (Windows)
	PHPModeModule   PHPRuntimeMode = "module"    // mod_php / ISAPI (not implemented)
	PHPModeDetached PHPRuntimeMode = "not_found" // nothing usable detected
)

// ExtensionInstallMode describes how a PHP extension is added.
type ExtensionInstallMode string

const (
	// ExtFromPackage: distro package (php8.3-redis).
	ExtFromPackage ExtensionInstallMode = "package"
	// ExtFromSource: phpize + pecl compile.
	ExtFromSource ExtensionInstallMode = "source"
	// ExtPrebuiltDLL: download a matching php_*.dll (Windows).
	ExtPrebuiltDLL ExtensionInstallMode = "prebuilt_dll"
)

// SchedulerKind describes where user cron tasks actually run.
type SchedulerKind string

const (
	SchedPanel    SchedulerKind = "panel" // our own in-process scheduler (always available)
	SchedCrontab  SchedulerKind = "crontab"
	SchedTaskschd SchedulerKind = "taskschd"
)

// FirewallBackend describes the host firewall implementation in use.
type FirewallBackend string

const (
	FirewallUFW       FirewallBackend = "ufw"
	FirewallFirewalld FirewallBackend = "firewalld"
	FirewallNftables  FirewallBackend = "nftables"
	FirewallWFP       FirewallBackend = "windows_filter_platform"
	FirewallNone      FirewallBackend = "none"
)

// RemoteAccess describes the admin access mechanisms a platform exposes.
type RemoteAccess string

const (
	AccessSSH   RemoteAccess = "ssh"
	AccessRDP   RemoteAccess = "rdp"
	AccessWinRM RemoteAccess = "winrm"
)

// Capabilities is the frozen-at-startup description of what this build+host can
// actually do. It is serialised verbatim by GET /api/v1/capabilities.
type Capabilities struct {
	OS           string `json:"os"`            // linux | windows | darwin
	OSFamily     string `json:"os_family"`     // debian | rhel | windows | unknown
	OSVersion    string `json:"os_version"`    // human readable
	Arch         string `json:"arch"`          // amd64 | arm64 | ...
	IsPrivileged bool   `json:"is_privileged"` // root / Administrator
	Hostname     string `json:"hostname"`

	WebServers    []WebServerName        `json:"web_servers"`  // implemented in M2
	PHPModes      []PHPRuntimeMode       `json:"php_modes"`    // fpm on unix, cgi on windows
	PHPVersions   []string               `json:"php_versions"` // installed, detected live
	PHPExtInstall []ExtensionInstallMode `json:"php_ext_install"`
	ReloadMode    ReloadMode             `json:"reload_mode"`

	Firewall              FirewallBackend `json:"firewall"`
	Schedulers            []SchedulerKind `json:"schedulers"`
	SupportsSubSecondCron bool            `json:"supports_sub_second_cron"` // panel scheduler only
	ServiceManager        string          `json:"service_manager"`          // systemd | windows_scm | none
	PackageManager        string          `json:"package_manager"`          // apt | dnf | none
	Permissions           string          `json:"permissions"`              // posix | acl
	RemoteAccess          []RemoteAccess  `json:"remote_access"`

	DatabaseEngines []string        `json:"database_engines"` // implemented in M3
	Features        map[string]bool `json:"features"`

	// Unavailable carries the honest reason for anything the UI must disable.
	// Key = feature id, value = message shown to the operator.
	Unavailable map[string]string `json:"unavailable"`
}

// Has reports whether a boolean feature flag is on.
func (c *Capabilities) Has(feat string) bool { return c.Features[feat] }

// Deny marks a feature unavailable with the reason the UI must display.
func (c *Capabilities) Deny(feat, reason string) {
	if c.Features != nil {
		c.Features[feat] = false
	}
	c.Unavailable[feat] = reason
}

// Allow marks a feature available and drops any previous denial.
func (c *Capabilities) Allow(feat string) {
	if c.Features != nil {
		c.Features[feat] = true
	}
	delete(c.Unavailable, feat)
}

// Feature identifiers referenced by both back-end gates and the front end.
const (
	FeatWebSite      = "site"
	FeatPHP          = "php"
	FeatPHPSourceExt = "php_ext_source"
	FeatSSL          = "ssl"
	FeatDatabase     = "database"
	FeatBackup       = "backup"
	FeatFirewall     = "firewall"
	FeatCron         = "cron"
	FeatTerminal     = "terminal"
	FeatMonitor      = "monitor"
	FeatAudit        = "audit"
	FeatSSHManager   = "ssh_manager"
	FeatFilePerms    = "file_posix_perms"
)
