// Package php discovers the PHP runtimes that are actually installed on the
// host, and describes them in the shape M2 needs: which versions exist, which
// SAPIs are wired up, where a version's pool directory and listen socket live.
//
// It exists because of what docs/功能设计.md §4.1's state table demands —
// `available` means 本版本、本机、此刻真能做 — and what
// internal/platform/detect.go's newBase() already promises: the bitmap must
// never claim a capability because it "usually exists". Before this package,
// internal/platform answered "php_modes = [fpm]" from a build tag, which is true
// on most Debian hosts and a lie on the one that never installed php8.3-fpm, and
// a lie is what turns a UI control into a dead button.
//
// Everything here takes a root prefix and a Runner. That is not
// over-engineering: the discovery logic has to be testable on a machine with no
// PHP installed at all, which is every CI box. The alternative — an untestable
// package that only works when someone happens to have php-fpm — is how M2 would
// ship an "available" that was never executed.
package php

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SAPI names as they appear in a Debian/Ubuntu PHP installation. These are the
// strings GET /api/v1/capabilities and `minipanel doctor` show, so they are part
// of the panel's vocabulary, not of the host's.
const (
	SAPICLI     = "cli"
	SAPIFPM     = "fpm"
	SAPICGI     = "cgi"
	SAPIApache2 = "apache2"
)

// sapiOrder is the order every SAPI list in this package comes out in, so a
// capability bitmap and an audit log cannot reorder between two runs. describe
// walks this slice instead of sorting afterwards.
var sapiOrder = []string{SAPICLI, SAPIFPM, SAPICGI, SAPIApache2}

// versionProbeTimeout bounds one `php -r` call. Kept small on purpose: doctor
// must stay usable on a loaded box.
const versionProbeTimeout = 3 * time.Second

// Runner executes a host binary and returns its stdout. Host is the live
// implementation; tests substitute a recorder so the logic can be exercised
// against a fake root tree.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// host runs the real binary with a short timeout. A hung php — a broken module
// loaded at startup is enough — must degrade discovery to "no evidence", not
// hang detection, because Detect() runs inside `minipanel doctor` and inside
// panel startup.
type host struct{}

func (host) Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// Host is the Runner that talks to the actual machine.
var Host Runner = host{}

// Root is the filesystem prefix discovery looks under. It is the same
// MINI_PANEL_ROOT that internal/platform's rooted() uses, so a developer can lay
// out a whole fake host — /etc/php, /usr/bin/php — under a temp directory and
// have the panel probe it as if it were the machine.
func Root() string { return os.Getenv("MINI_PANEL_ROOT") }

// Install is one PHP version found on the host, with only the facts that were
// actually observed. An empty field means "not seen", never "assumed" — which is
// why FpmBin stays empty on a cli-only install instead of pointing at a
// /usr/sbin/php-fpm8.3 that is not there.
type Install struct {
	Version string   `json:"version"` // "8.3"
	SAPIs   []string `json:"sapis"`   // in sapiOrder: cli, fpm, cgi, apache2
	Binary  string   `json:"binary"`  // /usr/bin/php8.3, or the default binary when that is what runs this version
	FpmBin  string   `json:"fpm_bin"` // /usr/sbin/php-fpm8.3, "" when there is no fpm
	ConfDir string   `json:"conf_dir"`
	PoolDir string   `json:"pool_dir"` // filled only when the pool directory exists
	Socket  string   `json:"socket"`   // filled only for a version that has fpm; a path, not a liveness claim
}

// Has reports whether this version exposes a SAPI.
func (i Install) Has(sapi string) bool {
	for _, s := range i.SAPIs {
		if s == sapi {
			return true
		}
	}
	return false
}

// Discover probes the host at Root(). It never fails: "no PHP here" is a normal,
// reportable answer for a static-site box, and M2's job is to say so rather than
// to guess. The second return value names binaries that exist but whose version
// could not be determined, so a caller can report the gap instead of dropping it.
func Discover() ([]Install, []string) { return DiscoverIn(Root(), Host) }

// DiscoverIn is the testable core: root is the filesystem prefix ("" for the
// real host) and run is how binaries get executed.
//
// Layout assumption, stated because it is what the probe actually looks at: the
// Debian/Ubuntu packaging (version directories under /etc/php, one binary per
// SAPI in /usr/{,s}bin). On other families the probe finds nothing rather than
// finding something it cannot name; the capability reason then says the version
// was not detected, which is honest, instead of reporting a path that does not
// exist.
func DiscoverIn(root string, run Runner) ([]Install, []string) {
	binDir := filepath.Join(root, "/usr/bin")
	versions := map[string]bool{}

	// Version directories are the first evidence: a maintainer who removed the
	// binary but left /etc/php/8.3 behind has a config tree we should not invent
	// a runtime for, so describe() still requires a runnable binary before it
	// reports a SAPI.
	for _, name := range dirNames(filepath.Join(root, "/etc/php")) {
		if isVersionDir(name) {
			versions[name] = true
		}
	}

	// The default-version symlink /usr/bin/php is the one name whose version is
	// not in the filename, so this is the only place the probe runs a binary.
	var unknown []string
	defaultBin, defaultVersion := "", ""
	for _, e := range runtimeBinaries(binDir) {
		if v, ok := versionOfBinary(e); ok {
			versions[v] = true
			continue
		}
		v, err := askVersion(run, filepath.Join(binDir, e))
		if err != nil || v == "" {
			unknown = append(unknown, filepath.Join(binDir, e))
			continue
		}
		versions[v] = true
		defaultBin, defaultVersion = filepath.Join(binDir, e), v
	}
	for _, e := range fileNames(filepath.Join(root, "/usr/sbin")) {
		if v, ok := versionOfFpmBinary(e); ok {
			versions[v] = true
		}
	}

	out := make([]Install, 0, len(versions))
	for v := range versions {
		i := describe(root, v, defaultBin, defaultVersion)
		if len(i.SAPIs) == 0 && i.Binary == "" {
			continue // a stray directory is not a runtime
		}
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return versionLess(out[a].Version, out[b].Version) })
	return out, unknown
}

// describe fills one Install from what is on disk right now.
func describe(root, version, defaultBin, defaultVersion string) Install {
	conf := filepath.Join(root, "/etc/php", version)
	i := Install{Version: version, ConfDir: conf}
	if p := filepath.Join(root, "/usr/bin", "php"+version); exists(p) {
		i.Binary = p
	} else if defaultBin != "" && defaultVersion == version {
		// Only the binary that said "8.3" about itself may stand in for 8.3.
		// Falling back to /usr/bin/php unconditionally would attribute whatever
		// the alternatives system currently points at to this version.
		i.Binary = defaultBin
	}
	if p := filepath.Join(root, "/usr/sbin", "php-fpm"+version); exists(p) {
		i.FpmBin = p
	}
	// A SAPI is present when its configuration tree exists AND something can run
	// it. Requiring both is the difference between "php-fpm is installed" and
	// "there is a directory someone left behind".
	for _, sapi := range sapiOrder {
		switch sapi {
		case SAPICLI:
			if dirExists(conf+"/"+sapi) && i.Binary != "" {
				i.SAPIs = append(i.SAPIs, sapi)
			}
		case SAPIFPM:
			if dirExists(conf+"/"+sapi) && i.FpmBin != "" {
				i.SAPIs = append(i.SAPIs, sapi)
			}
		case SAPICGI:
			if dirExists(conf+"/"+sapi) && exists(filepath.Join(root, "/usr/bin", "php-cgi"+version)) {
				i.SAPIs = append(i.SAPIs, sapi)
			}
		case SAPIApache2:
			if dirExists(conf+"/"+sapi) && exists(filepath.Join(root, "/usr/lib/apache2/modules", "libphp"+version+".so")) {
				i.SAPIs = append(i.SAPIs, sapi)
			}
		}
	}
	// pool.d is reported when it is really there; the write side uses PoolDir(),
	// which names the path whether or not it exists yet.
	if p := poolDirIn(root, version); dirExists(p) {
		i.PoolDir = p
	}
	if i.Has(SAPIFPM) {
		i.Socket = socketIn(root, version)
	}
	return i
}

// PoolDir is where an operator drops per-pool files for one version. Debian
// family layout, prefixed by MINI_PANEL_ROOT so a dev run can point at a tree it
// owns instead of /etc. It is the write target, so it returns the canonical path
// rather than "" when the directory is missing — Install.PoolDir is the field
// that says whether it was observed.
func PoolDir(version string) string { return poolDirIn(Root(), version) }

// SocketPath is the listen socket php-fpm creates for one version, which is what
// an nginx vhost has to point `fastcgi_pass` at. It is a path, not a liveness
// claim — SocketStatus(path) is the question "is anyone answering right now", and
// keeping the two apart is what stops the panel describing a stopped fpm as a
// backend a site can use.
func SocketPath(version string) string { return socketIn(Root(), version) }

func poolDirIn(root, version string) string {
	return filepath.Join(root, "/etc/php", version, "fpm", "pool.d")
}

func socketIn(root, version string) string {
	return filepath.Join(root, "/run/php", "php"+version+"-fpm.sock")
}

// Path states. A path is not a fact about the present moment: an operator who
// reads `socket /run/php/php8.3-fpm.sock` in a self-check reasonably assumes
// something is answering on the other end, and on the most common broken host
// (php-fpm installed but stopped, or removed and its socket file left behind)
// that assumption is exactly what M2's site handler would trip over. So this
// package answers two questions separately — where (PoolDir, SocketPath) and
// what is true of it right now (DirStatus, SocketStatus).
const (
	// DirStatus values.
	DirNone    = "none"    // nobody named a path, so there is nothing to look at
	DirPresent = "present" // the directory is on disk right now
	DirAbsent  = "absent"  // the path is the canonical Debian location; nothing is there
	DirNotDir  = "not_dir" // something else occupies that name

	// SocketStatus values.
	SocketNone      = "none"       // this version has no fpm, so no socket to report
	SocketAbsent    = "absent"     // no file: fpm never ran here, or this is not the Debian layout
	SocketNotSocket = "not_socket" // a regular file sits on that name — worse than "nobody listening"
	SocketIdle      = "idle"       // socket file present, no listening socket in the kernel table
	SocketListening = "listening"  // the kernel table has a LISTEN entry on this exact path
	SocketUnknown   = "unknown"    // /proc/net/unix unreadable: the honest answer is "cannot tell"
)

// procNetUnix is the kernel's unix socket table. It is deliberately not prefixed
// by MINI_PANEL_ROOT: what a dev run relocates is the panel's footprint (/etc,
// /var, /run), while this is state about the machine the process is standing on.
// Reading the real table is also what lets the tests below assert against truth
// rather than against a fixture of our own making.
const procNetUnix = "/proc/net/unix"

// DirStatus reports whether a directory this package named actually exists.
func DirStatus(path string) string {
	if path == "" {
		return DirNone
	}
	st, err := os.Stat(path)
	switch {
	case err != nil:
		return DirAbsent
	case st.IsDir():
		return DirPresent
	default:
		return DirNotDir
	}
}

// SocketStatus reports whether anyone is listening on the socket at path.
func SocketStatus(path string) string { return socketStatus(path, procNetUnix) }

// socketStatus splits "is there a file" from "is anyone listening", because those
// two disagree routinely: php-fpm leaves the socket file behind when it is
// stopped, and a panel that only stats the file would report a backend that is
// not there.
func socketStatus(path, table string) string {
	if path == "" {
		return SocketNone
	}
	st, err := os.Stat(path)
	if err != nil {
		return SocketAbsent
	}
	if st.Mode()&os.ModeSocket == 0 {
		return SocketNotSocket
	}
	listening, err := listeningSocketPaths(table)
	if err != nil {
		// Not being able to read the table is not evidence of nobody listening.
		return SocketUnknown
	}
	if listening[path] {
		return SocketListening
	}
	return SocketIdle
}

// listeningSocketPaths parses the kernel unix table and returns the bound paths
// in state SS_LISTENING ("01"). The line format is
// Num RefCount Protocol Flags Type St Inode Path, header included.
//
// Two limitations, both pointing the safe way: only stream listening sockets are
// matched, which is what php-fpm uses; and the kernel stores the path as the
// binding process saw it, so a listener from another mount namespace can show up
// as SocketIdle even though something is alive. Under-claiming is fine here, the
// reverse would be a lie about a running service.
func listeningSocketPaths(table string) (map[string]bool, error) {
	b, err := os.ReadFile(table)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[5] != "01" {
			continue
		}
		out[strings.Join(f[7:], " ")] = true
	}
	return out, nil
}

// Versions returns just the version strings, in the same order Discover does.
func Versions(installs []Install) []string {
	out := make([]string, 0, len(installs))
	for _, i := range installs {
		out = append(out, i.Version)
	}
	return out
}

// Modes maps a discovered SAPI set onto the capability vocabulary the bitmap
// uses, so internal/platform can report `php_modes` from evidence. Only fpm and
// cgi have a constant that means what it says here; the apache2 module handler
// is deliberately not folded into "cgi" — collapsing two different runtimes into
// one label is how an operator gets told the wrong thing.
func Modes(installs []Install) (fpm, cgi bool) {
	for _, i := range installs {
		if i.Has(SAPIFPM) {
			fpm = true
		}
		if i.Has(SAPICGI) {
			cgi = true
		}
	}
	return fpm, cgi
}

// askVersion is the only place this package executes a host binary, so it is the
// only place a hung or broken php can cost time. The answer has to look like a
// version or it is not accepted.
func askVersion(run Runner, binary string) (string, error) {
	out, err := run.Run(binary, "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(out)
	if !isVersionDir(v) {
		return "", fmt.Errorf("%q is not a php version", v)
	}
	return v, nil
}

// defaultBinaryName is the un-versioned entry the alternatives system points at.
const defaultBinaryName = "php"

// runtimeBinaries lists the entries in dir that can be a PHP runtime: exactly
// `php` and `php<major>.<minor>`. The narrow match is deliberate — /usr/bin also
// holds php-config, phpize and phar*, and reporting those as "a php binary we
// could not version" would be doctor lying about the host.
func runtimeBinaries(dir string) []string {
	var out []string
	for _, e := range fileNames(dir) {
		if e == defaultBinaryName {
			out = append(out, e)
			continue
		}
		if _, ok := versionOfBinary(e); ok {
			out = append(out, e)
		}
	}
	return out
}

// versionOfBinary reads "8.3" out of "php8.3"; ok is false for "php" and for
// anything else, so the caller decides whether to ask the binary.
func versionOfBinary(name string) (string, bool) {
	v := strings.TrimPrefix(name, "php")
	if v == name {
		return "", false
	}
	return v, isVersionDir(v)
}

func versionOfFpmBinary(name string) (string, bool) {
	v, ok := strings.CutPrefix(name, "php-fpm")
	if !ok {
		return "", false
	}
	return v, isVersionDir(v)
}

// isVersionDir accepts the "major.minor" form Debian uses in /etc/php.
func isVersionDir(s string) bool {
	major, minor, ok := strings.Cut(s, ".")
	if !ok || major == "" || minor == "" {
		return false
	}
	return digits(major) && digits(minor)
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// versionLess orders 8.10 after 8.9 — string order would put it first, and a
// flip-flopping "latest version" is exactly the kind of instability the panel
// promises not to have.
func versionLess(a, b string) bool {
	an, bn := versionParts(a), versionParts(b)
	for i := 0; i < 2; i++ {
		if an[i] != bn[i] {
			return an[i] < bn[i]
		}
	}
	return false
}

func versionParts(v string) [2]int {
	var p [2]int
	major, minor, _ := strings.Cut(v, ".")
	p[0], _ = strconv.Atoi(major)
	p[1], _ = strconv.Atoi(minor)
	return p
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func dirNames(dir string) []string { return entries(dir, true) }

func fileNames(dir string) []string { return entries(dir, false) }

// entries lists a directory, swallowing "no such directory": a host without
// /etc/php is a normal answer, and a probe that errored on it would be reporting
// the absence of a directory as a failure of the panel.
func entries(dir string, dirsOnly bool) []string {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range des {
		if d.IsDir() != dirsOnly {
			continue
		}
		out = append(out, d.Name())
	}
	return out
}
