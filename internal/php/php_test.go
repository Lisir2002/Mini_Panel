package php

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recRunner answers `php -r` with a fixed string and records every call, so the
// tests can assert the claim in DiscoverIn's comment: the bare default binary is
// the ONLY thing this package executes.
type recRunner struct {
	out   string
	err   error
	calls []string
}

func (r *recRunner) Run(name string, args ...string) (string, error) {
	r.calls = append(r.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	if r.err != nil {
		return "", r.err
	}
	return r.out, nil
}

// fixture lays out a fake host tree under t.TempDir(), so every assertion below
// is about the discovery logic rather than about what happens to be installed on
// the machine running the test.
type fixture struct {
	t    *testing.T
	root string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, root: t.TempDir()}
}

// at turns a fixture-relative path into the absolute path discovery reports.
func (f *fixture) at(p string) string { return filepath.Join(f.root, p) }

func (f *fixture) dirs(list ...string) {
	f.t.Helper()
	for _, d := range list {
		if err := os.MkdirAll(f.at(d), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
}

// files writes executables, creating their parents.
func (f *fixture) files(list ...string) {
	f.t.Helper()
	for _, p := range list {
		full := f.at(p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("#!/bin/sh\n"), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
}

// find returns the install with the given version, failing the test if absent.
func (f *fixture) find(got []Install, version string) Install {
	f.t.Helper()
	for _, i := range got {
		if i.Version == version {
			return i
		}
	}
	f.t.Fatalf("no install for %s in %v", version, got)
	return Install{}
}

func sapis(i Install) string { return strings.Join(i.SAPIs, ",") }

// TestFullDebianTree is the "everything installed" shape: two versions, one of
// them complete. It pins the ordering, the SAPI set and the two derived paths.
func TestFullDebianTree(t *testing.T) {
	f := newFixture(t)
	f.dirs("/etc/php/8.2/cli", "/etc/php/8.2/fpm/pool.d",
		"/etc/php/8.3/cli", "/etc/php/8.3/fpm/pool.d", "/etc/php/8.3/cgi", "/etc/php/8.3/apache2",
		"/etc/php/8.3/mods-available", "/etc/php/fpm-php8.3/conf.d")
	f.files("/usr/bin/php8.2", "/usr/bin/php8.3", "/usr/bin/php", "/usr/bin/php-cgi8.3",
		"/usr/sbin/php-fpm8.2", "/usr/sbin/php-fpm8.3",
		"/usr/lib/apache2/modules/libphp8.3.so")

	run := &recRunner{out: "8.3\n"}
	got, unknown := DiscoverIn(f.root, run)
	if len(unknown) != 0 {
		t.Errorf("unknown = %v, want none", unknown)
	}
	if len(run.calls) != 1 {
		t.Errorf("executed %d binaries (%v), want exactly 1 — only the default binary may be asked", len(run.calls), run.calls)
	}
	if len(got) != 2 {
		t.Fatalf("got %d installs, want 2: %v", len(got), got)
	}
	if got[0].Version != "8.2" || got[1].Version != "8.3" {
		t.Errorf("order = %s, %s", got[0].Version, got[1].Version)
	}

	a := f.find(got, "8.2")
	if sapis(a) != "cli,fpm" {
		t.Errorf("8.2 SAPIs = %v, want cli,fpm", a.SAPIs)
	}
	if a.Binary != f.at("/usr/bin/php8.2") || a.FpmBin != f.at("/usr/sbin/php-fpm8.2") {
		t.Errorf("8.2 binary = %q fpm_bin = %q", a.Binary, a.FpmBin)
	}
	if a.PoolDir != f.at("/etc/php/8.2/fpm/pool.d") {
		t.Errorf("8.2 pool_dir = %q", a.PoolDir)
	}
	if a.Socket != f.at("/run/php/php8.2-fpm.sock") {
		t.Errorf("8.2 socket = %q", a.Socket)
	}

	b := f.find(got, "8.3")
	if sapis(b) != "cli,fpm,cgi,apache2" {
		t.Errorf("8.3 SAPIs = %v, want sapiOrder", b.SAPIs)
	}
	if b.ConfDir != f.at("/etc/php/8.3") {
		t.Errorf("8.3 conf_dir = %q", b.ConfDir)
	}
	// /etc/php/fpm-php8.3 and mods-available are layout noise, not runtimes.
	for _, i := range got {
		if i.Version == "fpm-php8.3" || i.Version == "mods-available" {
			t.Fatalf("invented version %q from a non-version directory", i.Version)
		}
	}

	fpm, cgi := Modes(got)
	if !fpm || !cgi {
		t.Errorf("Modes() = fpm:%v cgi:%v, want both true", fpm, cgi)
	}
	if s := strings.Join(Versions(got), ","); s != "8.2,8.3" {
		t.Errorf("Versions() = %q", s)
	}
}

// TestCLITreeWithoutFPM is this repository's own dev host: PHP 8.3 cli with no
// php-fpm anywhere. The point of the M2 slice is that discovery answers "no fpm"
// here instead of repeating what a build tag assumed, because that answer is
// what turns the php capability from available into degraded.
func TestCLITreeWithoutFPM(t *testing.T) {
	f := newFixture(t)
	f.dirs("/etc/php/8.3/cli", "/etc/php/8.3/mods-available")
	f.files("/usr/bin/php8.3")

	got, unknown := DiscoverIn(f.root, &recRunner{})
	if len(unknown) != 0 {
		t.Fatalf("unknown = %v", unknown)
	}
	if len(got) != 1 {
		t.Fatalf("got %d installs, want 1", len(got))
	}
	i := got[0]
	if sapis(i) != "cli" {
		t.Errorf("SAPIs = %v, want [cli]", i.SAPIs)
	}
	if i.FpmBin != "" {
		t.Errorf("FpmBin = %q, must stay empty when there is no php-fpm binary", i.FpmBin)
	}
	if i.PoolDir != "" {
		t.Errorf("PoolDir = %q, must stay empty when the directory was not seen", i.PoolDir)
	}
	if i.Socket != "" {
		t.Errorf("Socket = %q, must stay empty without an fpm SAPI", i.Socket)
	}
	if fpm, cgi := Modes(got); fpm || cgi {
		t.Errorf("Modes() = fpm:%v cgi:%v on a cli-only host — php_modes would be a lie", fpm, cgi)
	}
}

// TestStrayConfigDirIsNotARuntime: removing the binary while leaving
// /etc/php/8.4 behind is a half-uninstalled host. Reporting 8.4 as a runtime
// would put a version in the site editor's dropdown that nothing can execute.
func TestStrayConfigDirIsNotARuntime(t *testing.T) {
	f := newFixture(t)
	f.dirs("/etc/php/8.4/cli", "/etc/php/8.4/fpm/pool.d")

	got, unknown := DiscoverIn(f.root, &recRunner{})
	if len(got) != 0 {
		t.Errorf("got %v, want no installs", got)
	}
	if len(unknown) != 0 {
		t.Errorf("unknown = %v", unknown)
	}
	// The write-side paths still name the canonical location, which is the
	// difference between "we saw it" and "this is where M2 would write".
	if PoolDir("8.4") == "" || SocketPath("8.4") == "" {
		t.Error("PoolDir/SocketPath must name a path even for an unobserved version")
	}
}

// TestUnresolvableDefaultBinaryIsReported: a runner that fails or answers with
// nonsense is the only way a version can go unknown, and it must come back as a
// named gap rather than be dropped silently — that list is what doctor prints.
func TestUnresolvableDefaultBinaryIsReported(t *testing.T) {
	f := newFixture(t)
	f.files("/usr/bin/php")

	cases := []struct {
		name string
		run  *recRunner
	}{
		{"binary fails", &recRunner{err: errors.New("context deadline exceeded")}},
		{"nonsense answer", &recRunner{out: "PHP 8.3.33 (cli) (NTS)\n"}},
		{"empty answer", &recRunner{out: ""}},
	}
	for _, tc := range cases {
		got, unknown := DiscoverIn(f.root, tc.run)
		if len(got) != 0 {
			t.Errorf("%s: got %v, want no installs", tc.name, got)
		}
		if len(unknown) != 1 || unknown[0] != f.at("/usr/bin/php") {
			t.Errorf("%s: unknown = %v, want the one unreadable binary", tc.name, unknown)
		}
	}
}

// TestToolsNamedPhpAreNotReportedAsRuntimes: /usr/bin on a Debian box also holds
// php-config, phpize and phar*. Calling any of them "a PHP binary we could not
// version" would be doctor inventing a problem the operator cannot fix.
func TestToolsNamedPhpAreNotReportedAsRuntimes(t *testing.T) {
	f := newFixture(t)
	f.files("/usr/bin/php-config", "/usr/bin/phpize", "/usr/bin/php-config8.3",
		"/usr/bin/php8.3", "/usr/bin/php-cgi8.3")

	got, unknown := DiscoverIn(f.root, &recRunner{})
	if len(unknown) != 0 {
		t.Errorf("unknown = %v, want only entries that could be a runtime", unknown)
	}
	if len(got) != 1 || got[0].Version != "8.3" {
		t.Fatalf("got %v, want just 8.3", got)
	}
	// No /etc/php/8.3 tree means no SAPI may be claimed, even though a php-cgi
	// binary is sitting right there.
	if sapis(got[0]) != "" {
		t.Errorf("SAPIs = %v, want none without a config tree", got[0].SAPIs)
	}
}

// TestDefaultBinaryOnlyClaimsItsOwnVersion pins the rule that exists because
// /usr/bin/php is a symlink the alternatives system can repoint at any time: a
// version may be attributed to it only when the binary itself said so.
func TestDefaultBinaryOnlyClaimsItsOwnVersion(t *testing.T) {
	f := newFixture(t)
	f.dirs("/etc/php/8.2/cli", "/etc/php/8.3/cli")
	f.files("/usr/bin/php")

	got, _ := DiscoverIn(f.root, &recRunner{out: "8.3"})
	if len(got) != 1 {
		t.Fatalf("got %v, want only 8.3 — 8.2 has no runnable binary", got)
	}
	if got[0].Version != "8.3" || got[0].Binary != f.at("/usr/bin/php") {
		t.Errorf("got %+v", got[0])
	}
}

// TestVersionOrderingIsNumeric: plain string order puts 8.10 before 8.9. A panel
// that picked "the newest version" from that list would switch a site's handler
// over on an unrelated re-scan.
func TestVersionOrderingIsNumeric(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"8.9", "8.10", true},
		{"8.10", "8.9", false},
		{"7.4", "8.3", true},
		{"8.3", "8.3", false},
	}
	for _, tc := range cases {
		if got := versionLess(tc.a, tc.b); got != tc.less {
			t.Errorf("versionLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.less)
		}
	}

	f := newFixture(t)
	for _, v := range []string{"8.10", "8.9", "7.4"} {
		f.dirs("/etc/php/" + v + "/cli")
		f.files("/usr/bin/php" + v)
	}
	got, _ := DiscoverIn(f.root, &recRunner{})
	if s := strings.Join(Versions(got), ","); s != "7.4,8.9,8.10" {
		t.Errorf("order = %q, want 7.4,8.9,8.10", s)
	}
}

// TestRootedPaths: MINI_PANEL_ROOT has to move the pool and socket paths too, or
// a dev run against a temp tree would write into the real /etc/php.
func TestRootedPaths(t *testing.T) {
	t.Setenv("MINI_PANEL_ROOT", "/tmp/mp-root-test")
	if got, want := PoolDir("8.3"), "/tmp/mp-root-test/etc/php/8.3/fpm/pool.d"; got != want {
		t.Errorf("PoolDir = %q, want %q", got, want)
	}
	if got, want := SocketPath("8.3"), "/tmp/mp-root-test/run/php/php8.3-fpm.sock"; got != want {
		t.Errorf("SocketPath = %q, want %q", got, want)
	}
	if Root() != "/tmp/mp-root-test" {
		t.Errorf("Root() = %q", Root())
	}
	t.Setenv("MINI_PANEL_ROOT", "")
	if got := PoolDir("8.3"); got != "/etc/php/8.3/fpm/pool.d" {
		t.Errorf("unrooted PoolDir = %q", got)
	}
}

// TestEmptyHostIsNotAnError: "no PHP here" must be a normal, empty answer. A
// static-site box is a valid deployment, and Detect() may not fail on it. The
// runner is poisoned so this also proves an empty tree never executes a binary.
func TestEmptyHostIsNotAnError(t *testing.T) {
	f := newFixture(t)
	run := &recRunner{err: errors.New("discovery must not exec anything here")}
	got, unknown := DiscoverIn(f.root, run)
	if len(got) != 0 || len(unknown) != 0 {
		t.Fatalf("got %v / %v, want two empty lists", got, unknown)
	}
	if len(run.calls) != 0 {
		t.Errorf("executed %v on a host with no PHP", run.calls)
	}
}

// TestSAPIOrderIsStable creates the tree in reverse order and re-runs discovery,
// so neither map iteration nor directory order can reorder what the bitmap and
// the audit log would record.
func TestSAPIOrderIsStable(t *testing.T) {
	f := newFixture(t)
	f.dirs("/etc/php/8.3/apache2", "/etc/php/8.3/cgi", "/etc/php/8.3/fpm/pool.d", "/etc/php/8.3/cli")
	f.files("/usr/bin/php8.3", "/usr/bin/php-cgi8.3", "/usr/sbin/php-fpm8.3",
		"/usr/lib/apache2/modules/libphp8.3.so")

	for n := 0; n < 20; n++ {
		got, _ := DiscoverIn(f.root, &recRunner{})
		if len(got) != 1 {
			t.Fatalf("run %d: got %v", n, got)
		}
		if s := sapis(got[0]); s != "cli,fpm,cgi,apache2" {
			t.Fatalf("run %d: SAPIs = %q", n, s)
		}
	}
}

// TestStatesOfTheReportedPaths runs against the real kernel table, which is why
// it reads like a probe rather than a table: the claim being tested is that
// SocketStatus does not report "listening" unless the kernel has a LISTEN entry
// on that exact path. The php-fpm failure this exists for is the ordinary one —
// the daemon was stopped or killed and its socket file is still sitting in
// /run/php, so anything that only stats the file calls a dead backend alive.
func TestStatesOfTheReportedPaths(t *testing.T) {
	if _, err := os.ReadFile(procNetUnix); err != nil {
		t.Skipf("没有 %s，listening/idle 这一半在本机无法验证：%v", procNetUnix, err)
	}
	dir := t.TempDir()

	if got := SocketStatus(""); got != SocketNone {
		t.Errorf("SocketStatus(\"\") = %q, want %q（没有人给出路径，这句话没有可检查的对象）", got, SocketNone)
	}
	if got := DirStatus(""); got != DirNone {
		t.Errorf("DirStatus(\"\") = %q, want %q", got, DirNone)
	}
	if got := DirStatus(dir); got != DirPresent {
		t.Errorf("DirStatus(existing dir) = %q, want %q", got, DirPresent)
	}
	if got := DirStatus(filepath.Join(dir, "never-created")); got != DirAbsent {
		t.Errorf("DirStatus(missing) = %q, want %q", got, DirAbsent)
	}

	// A regular file on the socket's name is a different problem than nothing
	// there, and it is the kind of thing that happens when someone unpacks a
	// backup over /run.
	regular := filepath.Join(dir, "php8.3-fpm.sock")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := SocketStatus(regular); got != SocketNotSocket {
		t.Errorf("SocketStatus(regular file) = %q, want %q", got, SocketNotSocket)
	}
	if got := DirStatus(regular); got != DirNotDir {
		t.Errorf("DirStatus(regular file) = %q, want %q", got, DirNotDir)
	}

	live := filepath.Join(dir, "live.sock")
	a, err := net.ResolveUnixAddr("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", a)
	if err != nil {
		t.Skipf("本机建不了 unix socket（%v），这一半验证不了", err)
	}
	// Go's unix listener unlinks its path at Close by default, which would make
	// the stale case below impossible to reach and would silently turn it into
	// "absent". A php-fpm that was SIGKILLed does not unlink anything: the inode
	// stays under /run and only the kernel's table entry goes away. Turning the
	// unlink off is what makes the test describe that host.
	ln.SetUnlinkOnClose(false)
	if got := SocketStatus(live); got != SocketListening {
		t.Errorf("SocketStatus while listening = %q, want %q", got, SocketListening)
	}
	// The stale-file case: closing the listener takes the entry out of the kernel
	// table but leaves the inode on disk. If this ever reports listening, the
	// panel would be describing a service that is not running.
	ln.Close()
	if got := SocketStatus(live); got != SocketIdle {
		t.Errorf("SocketStatus after the listener exited = %q, want %q（文件还在，内核里没人听）", got, SocketIdle)
	}
	if got := SocketStatus(filepath.Join(dir, "never-created")); got != SocketAbsent {
		t.Errorf("SocketStatus(missing) = %q, want %q", got, SocketAbsent)
	}
}

// TestSocketStatusUsesThePathColumnVerbatim is the parser test: two real socket
// files, a fabricated table that lists only one of them, and a row shape set
// chosen so a sloppy Fields() index would read the wrong column. Nothing here
// depends on what else the machine happens to have running.
func TestSocketStatusUsesThePathColumnVerbatim(t *testing.T) {
	dir := t.TempDir()
	named := filepath.Join(dir, "php 8.3-fpm.sock") // a space in the path: the Path column is the tail, not fields[7]
	other := filepath.Join(dir, "other.sock")
	for _, p := range []string{named, other} {
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Skipf("本机建不了 unix socket（%v）", err)
		}
		defer ln.Close()
	}
	table := filepath.Join(dir, "unix")
	body := "Num       RefCount Protocol Flags    Type St Inode Path\n" +
		"ffff0: 00000002 00000000 00010000 0001 01 111 " + named + "\n" + // LISTEN on the one we ask about
		"ffff1: 00000000 00000000 00000000 0001 03 222 " + other + "\n" + // CONNECTED, must not count
		"ffff2: 00000002 00000000 00010000 0001 01 333\n" + // unnamed socket, no path column
		"ffff3: 00000002 00000000 00010000 0001 01 444 " + filepath.Join(dir, "gone.sock") + "\n" // listed but not on disk
	if err := os.WriteFile(table, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := socketStatus(named, table); got != SocketListening {
		t.Errorf("socketStatus(named) = %q, want %q", got, SocketListening)
	}
	if got := socketStatus(other, table); got != SocketIdle {
		t.Errorf("socketStatus(connected-only entry) = %q, want %q（st=03 不是 LISTEN）", got, SocketIdle)
	}
	if got := socketStatus(named, filepath.Join(dir, "no-such-table")); got != SocketUnknown {
		t.Errorf("socketStatus(unreadable table) = %q, want %q（读不到就是不知道，不是没人听）", got, SocketUnknown)
	}
	listening, err := listeningSocketPaths(table)
	if err != nil {
		t.Fatal(err)
	}
	if len(listening) != 2 {
		t.Errorf("listening table = %v, want the two st=01 rows with a path", listening)
	}
}

// TestLiveHostIsSelfConsistent runs the real probe against the real machine. It
// has to pass on a box with no PHP at all, so it asserts only that whatever is
// reported is true — the guard against a fixture that passed while the host path
// was broken, and the test that makes `minipanel doctor`'s PHP line verifiable.
func TestLiveHostIsSelfConsistent(t *testing.T) {
	got, unknown := Discover()
	for _, i := range got {
		if i.Binary != "" {
			if st, err := os.Stat(i.Binary); err != nil {
				t.Errorf("%s: reported binary %q does not exist: %v", i.Version, i.Binary, err)
			} else if st.IsDir() {
				t.Errorf("%s: binary %q is a directory", i.Version, i.Binary)
			}
		}
		if i.PoolDir != "" {
			if st, err := os.Stat(i.PoolDir); err != nil || !st.IsDir() {
				t.Errorf("%s: pool_dir %q is not a directory", i.Version, i.PoolDir)
			}
		}
		if i.Has(SAPIFPM) != (i.FpmBin != "") {
			t.Errorf("%s: fpm SAPI and fpm_bin disagree (%v / %q)", i.Version, i.Has(SAPIFPM), i.FpmBin)
		}
		if !i.Has(SAPIFPM) && i.Socket != "" {
			t.Errorf("%s: socket %q reported without an fpm SAPI", i.Version, i.Socket)
		}
		if !inSapiOrder(i.SAPIs) {
			t.Errorf("%s: SAPIs %v are out of sapiOrder", i.Version, i.SAPIs)
		}
	}
	for _, p := range unknown {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("unknown entry %q does not exist either", p)
		}
	}
	// Modes() must be exactly the union of what the installs say.
	fpm, cgi := Modes(got)
	if fpm != hasAny(got, SAPIFPM) || cgi != hasAny(got, SAPICGI) {
		t.Errorf("Modes() = fpm:%v cgi:%v, installs say fpm:%v cgi:%v",
			fpm, cgi, hasAny(got, SAPIFPM), hasAny(got, SAPICGI))
	}
	if t.Failed() {
		t.Logf("host reported installs=%+v unknown=%v", got, unknown)
	}
}

// inSapiOrder reports whether list is a subsequence of sapiOrder.
func inSapiOrder(list []string) bool {
	n := 0
	for _, want := range sapiOrder {
		if n < len(list) && list[n] == want {
			n++
		}
	}
	return n == len(list)
}

func hasAny(installs []Install, sapi string) bool {
	for _, i := range installs {
		if i.Has(sapi) {
			return true
		}
	}
	return false
}
