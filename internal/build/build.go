// Package build carries version metadata stamped at link time.
package build

var (
	Version   = "0.1.0-dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// UserAgent is sent on outbound self-identification (none in M0: Mini Panel
// makes no third-party telemetry calls by design).
func UserAgent() string { return "MiniPanel/" + Version }
