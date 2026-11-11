package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/config"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

// CLI tests exist because the M0 audit found a defect no HTTP test could ever
// see: `minipanel init --port 29095 --bind 127.0.0.1` accepted the flags,
// ignored every one of them, wrote the defaults, and printed a banner that
// looked like it had honoured the request. Every assertion below reads the
// effect back from disk, which is what the next `serve` will use.
//
// MINI_PANEL_ROOT relocates /etc and /var into a temp dir (platform.rooted), so
// these tests never touch a real host footprint.

func isolated(t *testing.T) {
	t.Helper()
	t.Setenv("MINI_PANEL_ROOT", t.TempDir())
	t.Setenv("MINI_PANEL_DEBUG", "")
}

// readBack loads panel.json the way serve does: a flag that is parsed but not
// persisted is exactly the bug this file was written for.
func readBack(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(platform.Current().ConfigDir())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

func TestInitHonoursItsFlags(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--port", "29123", "--bind", "127.0.0.1",
		"--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	cfg := readBack(t)
	if cfg.Port != 29123 {
		t.Errorf("port = %d, want 29123 — a silently dropped flag is worse than no flag at all", cfg.Port)
	}
	if cfg.Bind != "127.0.0.1" {
		t.Errorf("bind = %q, want 127.0.0.1", cfg.Bind)
	}
	if cfg.TLS {
		t.Error("TLS still enabled despite --insecure-no-tls")
	}
	if err := sec.ValidateEntrance(cfg.Entrance); err != nil {
		t.Errorf("generated entrance %q rejected by our own validator: %v", cfg.Entrance, err)
	}
	if !strings.Contains(cfg.Entrance, "/") {
		t.Errorf("entrance %q has no leading slash", cfg.Entrance)
	}

	fi, err := os.Stat(config.Path(platform.Current().ConfigDir()))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("panel.json mode = %o, want 600 (it holds the entrance and the TLS switch)", perm)
	}
}

func TestInitRejectsUnknownAndExtraArgs(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--bogus"}); err == nil {
		t.Error("unknown flag accepted")
	}
	if err := dispatch([]string{"init", "surplus"}); err == nil {
		t.Error("positional argument accepted by a command that takes none")
	}
	if err := dispatch([]string{"nonsense-command"}); err == nil {
		t.Error("unknown subcommand accepted")
	}
}

func TestInitEntranceFlag(t *testing.T) {
	cases := []struct {
		name, flagArg, want string
		wantErr             bool
	}{
		{"explicit", "/myadmin", "/myadmin", false},
		{"leading slash added", "myadmin", "/myadmin", false},
		{"dash disables the entrance", "-", "", false},
		{"reserved path refused", "/api", "", true},
		{"too short refused", "/ab", "", true},
		{"traversal refused", `/../../etc`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolated(t)
			err := dispatch([]string{"init", "--insecure-no-tls", "--entrance", tc.flagArg})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("entrance %q accepted, want refusal", tc.flagArg)
				}
				return
			}
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			// The sentinel case is the one that matters: "no entrance" must never
			// be reinterpreted as "generate one for me".
			if got := readBack(t).Entrance; got != tc.want {
				t.Errorf("entrance = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResetEntranceKeepsConfigAndMirrorInStep(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := dispatch([]string{"reset-entrance", "--set", "/zzq4k7m2"}); err != nil {
		t.Fatalf("reset-entrance: %v", err)
	}
	if got := readBack(t).Entrance; got != "/zzq4k7m2" {
		t.Fatalf("entrance = %q, want /zzq4k7m2", got)
	}
	// The settings row is what the UI would show if the two ever disagreed, so
	// a reset has to move both.
	assertSetting(t, "panel.entrance", "/zzq4k7m2")

	if err := dispatch([]string{"reset-entrance", "--disable"}); err != nil {
		t.Fatalf("--disable: %v", err)
	}
	if got := readBack(t).Entrance; got != "" {
		t.Errorf("entrance = %q after --disable, want empty", got)
	}
	assertSetting(t, "panel.entrance", "")

	// --set and --disable together is a contradiction, not a precedence rule.
	if err := dispatch([]string{"reset-entrance", "--set", "/ab12cd34", "--disable"}); err == nil {
		t.Error("--set with --disable accepted; refusing is safer than picking one")
	}

	if err := dispatch([]string{"doctor"}); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if err := dispatch([]string{"doctor", "--json"}); err != nil {
		t.Fatalf("doctor --json: %v", err)
	}
}

func assertSetting(t *testing.T, key, want string) {
	t.Helper()
	st, err := store.Open(filepath.Join(platform.Current().DataDir(), "minipanel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	got, err := st.GetSetting(key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	if got != want {
		t.Errorf("setting %s = %q, want %q", key, got, want)
	}
}

func TestPasswdSetsMustChangeAndValidatesInput(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := dispatch([]string{"passwd", "admin", "--password", "First!2026pass"}); err != nil {
		t.Fatalf("passwd create: %v", err)
	}

	st, err := store.Open(filepath.Join(platform.Current().DataDir(), "minipanel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	u, err := st.UserByUsername("admin")
	st.Close()
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if !u.MustChangePW {
		t.Error("must_change_pw not set: a password passed over a shell is not one the operator chose")
	}

	// Username may lead the flags or trail them; the flag package stops at the
	// first positional, so both orders have to work, and two names must not.
	if err := dispatch([]string{"passwd", "--password", "Second!2026pass", "admin"}); err != nil {
		t.Errorf("trailing username rejected: %v", err)
	}
	if err := dispatch([]string{"passwd", "admin", "admin"}); err == nil {
		t.Error("two usernames accepted")
	}
	if err := dispatch([]string{"passwd", "bad name!", "--password", "Third!2026pass"}); err == nil {
		t.Error("invalid username accepted")
	}
	if err := dispatch([]string{"passwd", "admin", "--password", "short"}); err == nil {
		t.Error("weak password accepted: the CLI is the one path with no rate limit, so it must not be the bypass")
	}
	// No tty and an empty stdin under `go test`: reading yields nothing, and an
	// empty credential has to be refused rather than stored.
	if err := dispatch([]string{"passwd", "admin"}); err == nil {
		t.Error("empty piped password accepted")
	}
}

func TestSubcommandHelpIsNotAFailure(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{{"init", "-h"}, {"serve", "-h"}, {"doctor", "-h"},
		{"passwd", "-h"}, {"reset-entrance", "-h"}} {
		err := dispatch(args)
		if err != nil && !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%v = %v, want nil or flag.ErrHelp", args, err)
		}
	}
	// main maps flag.ErrHelp to exit 0; that mapping is asserted here rather
	// than in main() because main() calls os.Exit.
	if err := dispatch([]string{"version"}); err != nil {
		t.Errorf("version: %v", err)
	}
}

// TestUsageCoversEveryCommand keeps the help text from rotting: dispatch's
// switch and the usage block are two lists that must stay one list.
func TestUsageCoversEveryCommand(t *testing.T) {
	// reset-ips / reset-2fa joined the list with M1's §6.3 gaps; the lockout table
	// cross-checks these names against dispatch (lockout_test.go).
	for _, cmd := range []string{"serve", "init", "doctor", "passwd", "reset-entrance",
		"reset-ips", "reset-2fa", "version"} {
		if !strings.Contains(usage, "minipanel "+cmd) {
			t.Errorf("usage does not document %q", cmd)
		}
	}
	for _, f := range []string{"--insecure-no-tls", "--entrance", "--bind", "--port",
		"--password", "--json", "--set", "--disable"} {
		if !strings.Contains(usage, f) {
			t.Errorf("usage does not document %q", f)
		}
	}
}

// TestBannerReportsLiveConfigValues: the banner is the operator's only glance at
// what just started, so it must show the values in use — including a disabled
// entrance, which the old text hid behind an empty string.
func TestBannerReportsLiveConfigValues(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls", "--bind", "127.0.0.1",
		"--port", "29123", "--entrance", "-"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	e, err := bootstrap()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	defer e.st.Close()

	joined := strings.Join(bannerLines(e), "\n")
	for _, want := range []string{"29123", "127.0.0.1", "http://127.0.0.1:29123"} {
		if !strings.Contains(joined, want) {
			t.Errorf("banner missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "0.0.0.0") {
		t.Errorf("banner advertises 0.0.0.0 while bound to loopback:\n%s", joined)
	}
	// A blank entrance must read as disabled, not as a missing value.
	if !strings.Contains(joined, "未设置") {
		t.Errorf("disabled entrance not explained in banner:\n%s", joined)
	}
}

// TestResetIPsWritesOnlyWhatItIsTold covers the escape hatch for the one setting
// whose own enforcement path is the thing that broke: panel.ip_allowlist is
// checked in the session middleware, so a bad list refuses the request that
// would correct it. If reset-ips could guess, a typo in a recovery script would
// silently open the panel to every address.
func TestResetIPsWritesOnlyWhatItIsTold(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	// No flags must not mean "clear".
	if err := dispatch([]string{"reset-ips"}); err == nil {
		t.Error("reset-ips without --set/--clear did something; it should refuse")
	}
	assertSetting(t, "panel.ip_allowlist", "")

	if err := dispatch([]string{"reset-ips", "--set", "203.0.113.7,10.0.0.0/8"}); err != nil {
		t.Fatalf("reset-ips --set: %v", err)
	}
	assertSetting(t, "panel.ip_allowlist", "203.0.113.7\n10.0.0.0/8\n")

	if err := dispatch([]string{"reset-ips", "--clear"}); err != nil {
		t.Fatalf("reset-ips --clear: %v", err)
	}
	assertSetting(t, "panel.ip_allowlist", "")

	// Same rules as the API: hostnames would make the allow decision depend on
	// somebody else's DNS.
	for _, bad := range []string{"office.example.com", "1.2.3.4/33", "not-an-ip/99", "10.0.0.7/8/16"} {
		if err := dispatch([]string{"reset-ips", "--set", bad}); err == nil {
			t.Errorf("reset-ips accepted %q", bad)
		}
	}
	// The list must still be usable after a refusal, and readable by the
	// middleware: no partial write, no stray whitespace.
	assertSetting(t, "panel.ip_allowlist", "")
	if err := dispatch([]string{"reset-ips", "--set", "198.51.100.0/24"}); err != nil {
		t.Fatalf("reset-ips after refusals: %v", err)
	}
	if err := sec.ValidateIPAllowlist(mustSetting(t, "panel.ip_allowlist")); err != nil {
		t.Errorf("stored list no longer parses: %v", err)
	}

	if err := dispatch([]string{"reset-ips", "--set", "203.0.113.7", "--clear"}); err == nil {
		t.Error("--set with --clear accepted; refusing beats choosing for the operator")
	}
	if err := dispatch([]string{"reset-ips", "203.0.113.7"}); err == nil {
		t.Error("positional argument accepted; it would be silently ignored")
	}
}

// TestReset2FAClosesTheSecondFactorAndItsSessions covers the other lockout path:
// with totp_enabled set, the code is required at login and the secret exists only
// in this database. Turning it off has to also invalidate the sessions minted
// while it was on, or "the phone is gone" and "a session from the phone" survive
// side by side.
func TestReset2FAClosesTheSecondFactorAndItsSessions(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := dispatch([]string{"passwd", "admin", "--password", "First!2026pass"}); err != nil {
		t.Fatalf("passwd: %v", err)
	}

	path := filepath.Join(platform.Current().DataDir(), "minipanel.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.SetTOTP(1, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatalf("enable 2fa: %v", err)
	}
	if _, err := st.DB().Exec(`INSERT INTO sessions(id,user_id,created_at,expires_at,ip,ua,revoked)
		VALUES('alive',1,0,9999999999,'203.0.113.7','test',0)`); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	st.Close()

	// Disabling a second factor is a downgrade, so it cannot be the default.
	if err := dispatch([]string{"reset-2fa"}); err == nil {
		t.Error("reset-2fa without --clear did something; it should refuse")
	}
	if err := dispatch([]string{"reset-2fa", "--clear", "--user", "ghost"}); err == nil {
		t.Error("reset-2fa accepted a username that does not exist")
	}
	if err := dispatch([]string{"reset-2fa", "--clear"}); err != nil {
		t.Fatalf("reset-2fa --clear: %v", err)
	}

	st, err = store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()
	u, err := st.UserByUsername("admin")
	if err != nil {
		t.Fatalf("read user: %v", err)
	}
	if u.TOTPEnabled || u.TOTPSecret != "" {
		t.Errorf("2FA still enabled after reset (enabled=%v secret=%q)", u.TOTPEnabled, u.TOTPSecret)
	}
	var revoked int
	if err := st.DB().QueryRow(`SELECT revoked FROM sessions WHERE id='alive'`).Scan(&revoked); err != nil {
		t.Fatalf("read session: %v", err)
	}
	if revoked != 1 {
		t.Error("session minted while 2FA was on survived the reset")
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe. The recovery
// commands print straight through fmt, and their output is a claim about
// behaviour, so it has to be readable to be asserted on.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	callErr := fn()
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("drain stdout: %v", err)
	}
	_ = r.Close()
	return buf.String(), callErr
}

// TestRecoveryCommandsTellTheTruthAboutRestarting pins the one part of these
// commands a green test suite cannot catch on its own: the sentence after the
// write. panel.ip_allowlist, the TOTP secret and must_change_pw are re-read per
// request, so promising a restart there sends the operator off to look for a
// change that has already taken effect; panel.entrance is bootstrap config held
// in memory by the running process, so leaving the restart out would have them
// refresh a page that genuinely has not moved. A live run caught the first of
// these — reset-ips said "重启面板生效" while the very next request, with no
// restart, was already allowed through.
func TestRecoveryCommandsTellTheTruthAboutRestarting(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := dispatch([]string{"passwd", "admin", "--password", "First!2026pass"}); err != nil {
		t.Fatalf("passwd: %v", err)
	}

	live := []struct {
		name string
		args []string
		want string
	}{
		{"reset-ips --set", []string{"reset-ips", "--set", "203.0.113.7"}, "下一条请求就生效"},
		{"reset-ips --clear", []string{"reset-ips", "--clear"}, "下一条请求就生效"},
		{"reset-2fa --clear", []string{"reset-2fa", "--clear"}, "立即生效"},
	}
	for _, tc := range live {
		out, err := captureStdout(t, func() error { return dispatch(tc.args) })
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, out)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s does not say it applies immediately (want %q):\n%s", tc.name, tc.want, out)
		}
		if strings.Contains(out, "重启面板生效") {
			t.Errorf("%s promises a restart it does not need:\n%s", tc.name, out)
		}
	}

	// The entrance is the opposite case: the value is written to panel.json and
	// the running server keeps the one it loaded at startup, so without a restart
	// the new entrance is not served — the message has to say so.
	out, err := captureStdout(t, func() error {
		return dispatch([]string{"reset-entrance", "--set", "/recovdoor1"})
	})
	if err != nil {
		t.Fatalf("reset-entrance: %v\n%s", err, out)
	}
	if !strings.Contains(out, "需重启面板生效") {
		t.Errorf("reset-entrance hides the restart it genuinely needs:\n%s", out)
	}
	if got := readBack(t).Entrance; got != "/recovdoor1" {
		t.Errorf("entrance on disk = %q, want /recovdoor1", got)
	}
}

// mustSetting is the read-back half of the assertions above.
func mustSetting(t *testing.T, key string) string {
	t.Helper()
	st, err := store.Open(filepath.Join(platform.Current().DataDir(), "minipanel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	v, err := st.GetSetting(key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	return v
}
