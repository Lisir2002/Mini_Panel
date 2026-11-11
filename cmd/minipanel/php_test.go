package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/php"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// doctorPHP is the shape of `minipanel doctor --json` this file depends on. Only
// the keys the assertions read are declared, so a renamed key fails here instead
// of silently unmarshalling into nothing.
type doctorPHP struct {
	Caps struct {
		PHPVersions []string `json:"php_versions"`
		PHPModes    []string `json:"php_modes"`
		Features    map[string]struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
			Fix    string `json:"fix_action"`
			Verify string `json:"verify"`
		} `json:"features"`
	} `json:"capabilities"`
	CTLVersions []string `json:"php_ctl_versions"`
	PoolDir     string   `json:"php_pool_dir"`
	PoolState   string   `json:"php_pool_state"`
	Socket      string   `json:"php_socket"`
	SocketState string   `json:"php_socket_state"`
	Note        string   `json:"php_note"`
}

func runDoctorJSON(t *testing.T) doctorPHP {
	t.Helper()
	out, err := captureStdout(t, func() error { return dispatch([]string{"doctor", "--json"}) })
	if err != nil {
		t.Fatalf("doctor --json: %v", err)
	}
	var d doctorPHP
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("decode doctor json: %v", err)
	}
	return d
}

// TestDoctorPHPCtlLineIsTheInterface pins the two PHP answers in one binary
// against each other. The capability bitmap comes from internal/php's discovery
// inside Detect(); the php_ctl_* keys come from platform.PHPCtl, the interface
// M2's write side will use. If either ever stops being evidence — a hardcode, a
// cache, a build tag — the two lists part and this test says so.
func TestDoctorPHPCtlLineIsTheInterface(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}

	d := runDoctorJSON(t)
	if strings.Join(d.Caps.PHPVersions, " ") != strings.Join(d.CTLVersions, " ") {
		t.Errorf("bitmap php_versions=%v but PHPCtl said %v under MINI_PANEL_ROOT",
			d.Caps.PHPVersions, d.CTLVersions)
	}
	if len(d.Caps.PHPVersions) != 0 {
		t.Fatalf("an empty root must not report versions, got %v — discovery is reading the real host",
			d.Caps.PHPVersions)
	}
	if len(d.Caps.PHPModes) != 0 {
		t.Errorf("php_modes = %v on a root with no PHP, want empty", d.Caps.PHPModes)
	}
	f := d.Caps.Features["php"]
	if f.State != "unavailable" {
		t.Errorf("php state = %q with nothing discovered, want unavailable (degraded would claim a working main path)", f.State)
	}
	if !strings.Contains(f.Reason, "M2") {
		t.Errorf("reason %q does not tell the operator when this arrives", f.Reason)
	}
	if d.PoolDir != "" || d.Socket != "" {
		t.Errorf("pool/socket = %q / %q for a version that was not detected", d.PoolDir, d.Socket)
	}
	// With no path to look at, the two state keys still answer "what did you
	// check" — "none" is the one answer that does not pretend there was something
	// on disk to stat.
	if d.PoolState != "none" || d.SocketState != "none" {
		t.Errorf("pool_state/socket_state = %q / %q on a root with no version, want none / none",
			d.PoolState, d.SocketState)
	}
	if d.Note != "" {
		t.Errorf("note = %q although this platform implements PHPCtl", d.Note)
	}

	plain, err := captureStdout(t, func() error { return dispatch([]string{"doctor"}) })
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	line := labelled(t, plain, "PHP")
	if !strings.Contains(line, "未检测到可运行的 PHP") {
		t.Errorf("PHP line = %q, want the honest empty answer", line)
	}
	// The 注意 line is only for a contradiction between the two sources; printing
	// it on a healthy host would train the operator to ignore it.
	if strings.Contains(plain, "注意：") {
		t.Errorf("doctor raised a PHP contradiction on a consistent run:\n%s", plain)
	}
}

// TestDoctorPHPRootedHostNamesTheVersion is the degraded path end to end: a fake
// host with a cli-only PHP must produce a bitmap that says so, a self-check line
// that prints the version, and the two agreeing.
func TestDoctorPHPRootedHostNamesTheVersion(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "/etc/php/8.3/cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "/usr/bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "php8.3"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MINI_PANEL_ROOT", root)
	t.Setenv("MINI_PANEL_DEBUG", "")

	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	d := runDoctorJSON(t)
	if strings.Join(d.CTLVersions, " ") != "8.3" {
		t.Fatalf("PHPCtl said %v, want 8.3 from the rooted tree", d.CTLVersions)
	}
	if strings.Join(d.Caps.PHPVersions, " ") != "8.3" {
		t.Errorf("bitmap php_versions = %v, want 8.3", d.Caps.PHPVersions)
	}
	f := d.Caps.Features["php"]
	if f.State != "degraded" {
		t.Errorf("php state = %q, want degraded: a runtime was found, a handler was not", f.State)
	}
	if !strings.Contains(f.Reason, "8.3") || !strings.Contains(f.Reason, "fpm") {
		t.Errorf("reason %q must name both the detected version and the missing backend", f.Reason)
	}
	if f.Fix != "" {
		t.Errorf("fix_action = %q: §4.2 forbids this field from carrying a package name, and the panel installs nothing", f.Fix)
	}
	if !strings.Contains(f.Verify, "doctor") || !strings.Contains(f.Verify, "capabilities") {
		t.Errorf("verify = %q, want the two read-only re-check paths", f.Verify)
	}
	// Paths are one claim, states are the other. PHPCtl still names the Debian
	// layout under the root; the two state keys must report what a stat right now
	// finds there — and on a cli-only fake host that is nothing at all.
	if !strings.HasSuffix(d.PoolDir, "/etc/php/8.3/fpm/pool.d") || !strings.HasSuffix(d.Socket, "/run/php/php8.3-fpm.sock") {
		t.Errorf("pool=%q socket=%q, want the rooted Debian layout", d.PoolDir, d.Socket)
	}
	if d.PoolState != "absent" {
		t.Errorf("pool_state = %q, want absent: this host has no fpm, so its pool.d was never created", d.PoolState)
	}
	if d.SocketState != "absent" {
		t.Errorf("socket_state = %q, want absent: nothing is listening and no file was left behind", d.SocketState)
	}

	plain, err := captureStdout(t, func() error { return dispatch([]string{"doctor"}) })
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	line := labelled(t, plain, "PHP")
	for _, want := range []string{"8.3", "pool", "socket", "磁盘上还没有", "文件不存在", "——路径来自 PHPCtl，状态是此刻现场读的"} {
		if !strings.Contains(line, want) {
			t.Errorf("PHP line %q lacks %q", line, want)
		}
	}
	// The sentence this slice retired: it used to say the socket's liveness was
	// not checked, which was true then and is false now. If it comes back, the
	// reading stopped being evidence-based.
	if strings.Contains(line, "未校验 socket 是否存活") {
		t.Errorf("PHP line %q still claims the socket was not checked:\n%s", line, plain)
	}
	if strings.Contains(plain, "注意：") {
		t.Errorf("doctor raised a PHP contradiction while the two sources agree:\n%s", plain)
	}
}

// labelled returns the doctor line whose label is `want`, so an assertion can
// fail on the line it actually read.
func labelled(t *testing.T, out, want string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), want) {
			return line
		}
	}
	t.Fatalf("no %q line in doctor output:\n%s", want, out)
	return ""
}

// fpmRoot lays out a rooted host on which php8.3-fpm really is installed: the
// config tree, the sbin binary, the pool directory and the /run/php directory
// all exist, so PHPCtl's two paths name things that are there. It returns the
// root and the socket path the panel will go and look at.
func fpmRoot(t *testing.T) (root, socket string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"/etc/php/8.3/cli", "/etc/php/8.3/fpm/pool.d", "/usr/bin", "/usr/sbin", "/run/php"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"/usr/bin/php8.3", "/usr/sbin/php-fpm8.3"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(root, "/run/php/php8.3-fpm.sock")
}

// bindSocket is the one way these tests make a socket inode, and the
// SetUnlinkOnClose(false) is the point of it: Go's default listener deletes its
// path at Close, which would turn "stopped fpm" into "no fpm here" and hide the
// state this test exists to cover. A php-fpm that was killed leaves exactly what
// this leaves behind.
func bindSocket(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	a, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", a)
	if err != nil {
		t.Skipf("本机建不了 unix socket（%v），socket 存活这一半验证不了", err)
	}
	ln.SetUnlinkOnClose(false)
	return ln
}

// TestDoctorTellsStoppedFpmApartFromRunningFpm is the claim this slice exists
// for: the same host, the same paths, two different kernel states, and doctor
// must say which one it is looking at.
func TestDoctorTellsStoppedFpmApartFromRunningFpm(t *testing.T) {
	t.Run("文件在但没人听", func(t *testing.T) {
		root, socket := fpmRoot(t)
		bindSocket(t, socket).Close()
		plain := doctorForRootedFpm(t, root)

		if !strings.Contains(plain, "文件在但内核里没人听") {
			t.Errorf("doctor did not report a stale socket:\n%s", plain)
		}
		// Both of those are the same host's same two paths; the difference is only
		// in the kernel table, so the pool line must still read "present".
		if strings.Contains(plain, "内核里有进程在听") {
			t.Errorf("doctor claimed a listener that is not there:\n%s", plain)
		}
	})

	t.Run("真的有进程在听", func(t *testing.T) {
		root, socket := fpmRoot(t)
		ln := bindSocket(t, socket)
		defer ln.Close()
		plain := doctorForRootedFpm(t, root)

		if !strings.Contains(plain, "内核里有进程在听") {
			t.Errorf("doctor did not report the listener it can see:\n%s", plain)
		}
		if strings.Contains(plain, "文件在但内核里没人听") {
			t.Errorf("doctor called a live backend stopped:\n%s", plain)
		}
	})

	t.Run("两个状态各自对应一个 json 值", func(t *testing.T) {
		root, socket := fpmRoot(t)
		bindSocket(t, socket).Close()
		t.Setenv("MINI_PANEL_ROOT", root)
		t.Setenv("MINI_PANEL_DEBUG", "")
		if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
			t.Fatalf("init: %v", err)
		}
		d := runDoctorJSON(t)
		if d.PoolState != "present" {
			t.Errorf("pool_state = %q while the rooted tree has pool.d at %q", d.PoolState, d.PoolDir)
		}
		if d.SocketState != "idle" {
			t.Errorf("socket_state = %q, want idle: %q exists but nobody is listening", d.SocketState, socket)
		}
		found := false
		for _, m := range d.Caps.PHPModes {
			if m == "fpm" {
				found = true
			}
		}
		if !found {
			t.Errorf("php_modes = %v, want fpm in it: this fixture has /usr/sbin/php-fpm8.3 and /etc/php/8.3/fpm", d.Caps.PHPModes)
		}
		// fpm is in the bitmap, so the kernel table contradicts nothing here — the
		// 注意 line stays off on a host whose two PHP answers agree.
		plain := doctorText(t)
		if strings.Contains(plain, "注意：") {
			t.Errorf("doctor raised a contradiction on a host whose two PHP answers agree:\n%s", plain)
		}
	})
}

// doctorForRootedFpm runs the whole self-check against a rooted host and returns
// its text, so the assertions above read the sentence an operator would read.
func doctorForRootedFpm(t *testing.T, root string) string {
	t.Helper()
	t.Setenv("MINI_PANEL_ROOT", root)
	t.Setenv("MINI_PANEL_DEBUG", "")
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, err := captureStdout(t, func() error { return dispatch([]string{"doctor"}) })
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !strings.Contains(out, "8.3") {
		t.Fatalf("doctor did not see the rooted fixture's PHP 8.3:\n%s", out)
	}
	return out
}

func doctorText(t *testing.T) string {
	t.Helper()
	out, err := captureStdout(t, func() error { return dispatch([]string{"doctor"}) })
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	return out
}

// TestSocketListeningWithoutFpmModeIsAContradiction pins the fourth rule of
// phpBitmapMismatch without depending on what the machine running the test
// happens to have listening: a socket the kernel says is being listened to, and a
// bitmap that cannot name fpm as an available backend. That pair is what a
// non-Debian php-fpm produces, and the operator has to be told the two readings
// disagree instead of picking a site target and getting a 502.
func TestSocketListeningWithoutFpmModeIsAContradiction(t *testing.T) {
	isolated(t)
	caps, err := platform.Current().Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	caps.Degrade(platform.FeatPHP, "test fixture：见 reason", "", "")
	caps.PHPVersions = []string{"8.3"}
	caps.PHPModes = nil

	base := phpProbeResult{versions: []string{"8.3"}, socket: "/run/php/php8.3-fpm.sock", socketState: php.SocketListening}
	got := phpBitmapMismatch(caps, base)
	if got == "" {
		t.Fatal("a listening socket with no fpm in the bitmap is exactly the contradiction this rule is for, and it said nothing")
	}
	for _, want := range []string{"LISTEN", "php_modes", "非 Debian 布局"} {
		if !strings.Contains(got, want) {
			t.Errorf("contradiction line %q lacks %q", got, want)
		}
	}

	// Same fixture, socket file present but nobody listening: the two readings no
	// longer contradict each other, so the line must go silent. Printing it here
	// would be the boy-who-cried-wolf failure mode this note exists to avoid.
	base.socketState = php.SocketIdle
	if got := phpBitmapMismatch(caps, base); got != "" {
		t.Errorf("a stopped fpm is not a contradiction between the bitmap and the kernel table, got %q", got)
	}
}
