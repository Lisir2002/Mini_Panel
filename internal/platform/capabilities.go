// Package platform isolates every OS-specific fact behind an interface, so that
// internal/core never contains a `runtime.GOOS` branch.
//
// Design rule (docs/技术选型与MVP规格.md §2): the UI renders from the capability
// bitmap below and nothing else. A capability that does not exist on the current
// platform must be reported as absent with a human-readable reason — it must
// never be rendered as a control that silently does nothing.
package platform

import "strings"

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

// FeatureState is the four-state answer the front end renders from. It replaces
// the M0 boolean, which could only say "yes"/"no" and therefore kept producing
// the two failures the research pass found in the reference panels: a control
// that is clickable and does nothing, or a module that is simply hidden so the
// operator cannot tell "not here" from "not on this machine".
type FeatureState string

const (
	// StateAvailable: this build, on this host, right now really does the thing.
	StateAvailable FeatureState = "available"
	// StateDegraded: the main path works but a sub-path does not, or a
	// prerequisite is missing that we can name (and sometimes fix).
	StateDegraded FeatureState = "degraded"
	// StateUnavailable: this version has not implemented it, or the host cannot
	// satisfy it. Never hidden from the operator — rendered disabled, with a
	// reason they can read.
	StateUnavailable FeatureState = "unavailable"
	// StateForeign: the object exists on the host but was not created by the
	// panel, so it is presented read-only (a vhost written by Docker, a rule set
	// by hand). See docs/功能设计.md §5.3.
	StateForeign FeatureState = "foreign"
)

// Feature is one entry of the capability bitmap.
//
// The invariant the whole contract rests on: State != available ⇒ Reason is
// non-empty. It is enforced here rather than only in a test — Deny("") stores a
// self-reporting reason instead of a blank — because a blank reason is what
// forces a UI to invent text, which is the dishonesty this struct exists to
// prevent. FixAction and Verify are optional ("") and bounded by
// docs/功能设计.md §4.2: a panel action, a copyable command, or a read-only
// re-check path. Never an arbitrary package name, URL or command.
type Feature struct {
	State     FeatureState `json:"state"`
	Reason    string       `json:"reason"`
	FixAction string       `json:"fix_action"`
	Verify    string       `json:"verify"`
}

// noReasonStored is what an unexplained denial becomes. Seeing it in the UI is a
// bug report, not an operator problem: the panel failed to say why.
const noReasonStored = "面板未说明该项为何不可用，这是本项目的缺陷（请在仓库提 issue 并附上 /api/v1/capabilities 的返回）"

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
	PHPModes      []PHPRuntimeMode       `json:"php_modes"`    // Linux: from internal/php detection; Windows: still a build-tag constant
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

	DatabaseEngines []string `json:"database_engines"` // implemented in M3

	// Features is the whole contract: one entry per capability key, each carrying
	// its state and, for anything not available, the reason the operator sees.
	// M0 split this into `features` (bool) + `unavailable` (reason) and the split
	// was the bug — nothing stopped a key being off in one map and absent from
	// the other.
	Features map[string]Feature `json:"features"`
}

// State reports the state of a key. An unknown key reports unavailable rather
// than a made-up fifth state: the front end must never render a control for
// something the panel did not declare, and capabilities_test.go is what stops a
// declared key from going undeclared here.
func (c *Capabilities) State(feat string) FeatureState {
	f, ok := c.Features[feat]
	if !ok {
		return StateUnavailable
	}
	return f.State
}

// Has reports whether a capability is genuinely available. Degraded is not
// available for gating purposes: a handler that would half-succeed has to say so
// in its own response, not accept the click because a sub-feature exists.
func (c *Capabilities) Has(feat string) bool { return c.State(feat) == StateAvailable }

// Reason returns the sentence the UI shows, "" when the capability is available.
func (c *Capabilities) Reason(feat string) string { return c.Features[feat].Reason }

// set writes one entry, keeping the non-empty-reason invariant on every
// non-available state.
func (c *Capabilities) set(feat string, st FeatureState, reason, fix, verify string) {
	if c.Features == nil {
		c.Features = map[string]Feature{}
	}
	if st != StateAvailable && strings.TrimSpace(reason) == "" {
		reason = noReasonStored
	}
	if st == StateAvailable {
		reason, fix, verify = "", "", ""
	}
	c.Features[feat] = Feature{State: st, Reason: reason, FixAction: fix, Verify: verify}
}

// Deny marks a feature unavailable with the reason the UI must display.
func (c *Capabilities) Deny(feat, reason string) {
	c.set(feat, StateUnavailable, reason, "", "")
}

// Degrade marks a feature usable on its main path but short of something, with
// the missing part named. fix/verify follow §4.2 and may be "".
func (c *Capabilities) Degrade(feat, reason, fix, verify string) {
	c.set(feat, StateDegraded, reason, fix, verify)
}

// Foreign marks a feature whose objects exist but are not the panel's to write.
func (c *Capabilities) Foreign(feat, reason string) {
	c.set(feat, StateForeign, reason, "", "")
}

// Allow marks a feature available and drops its reason, fix action and re-check
// path: an available capability that still carries a "how to fix" is a stale
// bitmap, which is the state a UI would render as a dead button.
func (c *Capabilities) Allow(feat string) { c.set(feat, StateAvailable, "", "", "") }

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
