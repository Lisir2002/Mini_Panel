package main

import (
	"errors"
	"flag"
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
	for _, cmd := range []string{"serve", "init", "doctor", "passwd", "reset-entrance", "version"} {
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
