package platform

// Platform is the seam between the portable core and the host OS. Anything that
// differs between Linux and Windows lives behind this interface (or behind
// Capabilities), never inside internal/core.
//
// M0 implements detection and paths only. The mutator interfaces below are
// declared now so that Milestone 2 (sites) does not have to reshape the core:
// each one gets a linux/ and a windows/ implementation.
type Platform interface {
	// ID returns "linux", "windows" or "darwin".
	ID() string
	// Detect probes the live host and returns the capability bitmap.
	Detect() (*Capabilities, error)

	// ConfigDir holds panel.conf; DataDir holds minipanel.db, TLS material and
	// the entrance secret; LogDir holds rotating logs.
	ConfigDir() string
	DataDir() string
	LogDir() string
	// SiteRoot is the default document root parent for new sites.
	SiteRoot() string
	// BackupRoot is the default on-disk backup location.
	BackupRoot() string
}

// ServiceManager installs/removes Mini Panel as a boot service.
type ServiceManager interface {
	Install() error
	Remove() error
	Start() error
	Stop() error
	Status() (string, error)
}

// WebServerCtl arrives in M2.
type WebServerCtl interface {
	Name() WebServerName
	TestConfig() error
	Reload() error
	Restart() error
}

// FirewallCtl arrives in M4. Snapshot-before-change is mandatory: the firewall
// provider must be able to restore the exact rule set it replaced.
type FirewallCtl interface {
	Backend() FirewallBackend
	Snapshot() ([]byte, error)
	Restore(snap []byte) error
	ListRules() ([]FirewallRule, error)
	Apply(rule FirewallRule) error
	Remove(rule FirewallRule) error
}

// FirewallRule is the platform-neutral rule shape (mirrors the field set the
// BaoTa UI exposes: protocol/port/source/policy/direction/note).
type FirewallRule struct {
	Protocol  string `json:"protocol"`  // tcp | udp
	Port      string `json:"port"`      // "80", "80,88", "90-99"
	Source    string `json:"source"`    // CIDR or empty for any
	Policy    string `json:"policy"`    // accept | drop
	Direction string `json:"direction"` // in | out
	Note      string `json:"note"`
}

// PHPCtl arrives in M2, with the fpm/cgi split expressed through Capabilities.
type PHPCtl interface {
	Versions() ([]string, error)
	PoolDir(version string) string
	SocketPath(version string) string
}
