//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/php"
)

// These tests exist because the M2 rule in docs/里程碑.md is about where an
// answer comes from, not what it says: `php` and its sub-capabilities may only
// be reported from live Detect() evidence. The assertions below are written so
// that the previous implementation — `php_modes = [fpm]` and
// `php_ext_install = [package, source]` appended unconditionally — fails them on
// a cli-only box, which is this repository's own dev host.

func TestDetectPHPFieldsMatchDiscovery(t *testing.T) {
	caps, err := Current().Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	installs, _ := php.Discover()

	if got, want := strings.Join(caps.PHPVersions, ","), strings.Join(php.Versions(installs), ","); got != want {
		t.Errorf("php_versions = %q, discovery says %q", got, want)
	}
	fpm, cgi := php.Modes(installs)
	want := []PHPRuntimeMode{}
	if fpm {
		want = append(want, PHPModeFPM)
	}
	if cgi {
		want = append(want, PHPModeCGI)
	}
	if got := caps.PHPModes; len(got) != len(want) {
		t.Fatalf("php_modes = %v, discovery says %v — a mode nobody probed for is exactly the lie M2 forbids", got, want)
	}
	for i, m := range want {
		if caps.PHPModes[i] != m {
			t.Errorf("php_modes[%d] = %q, want %q", i, caps.PHPModes[i], m)
		}
	}

	// `available` is not reachable from this slice: discovering a runtime is not
	// serving a site through it, and internal/platform/capabilities_test.go's
	// whitelist would reject the claim too.
	switch st := caps.State(FeatPHP); {
	case st == StateAvailable:
		t.Error("php reported available while the pool/vhost write path is unshipped")
	case st == StateDegraded && len(installs) == 0:
		t.Error("php degraded with nothing discovered — degraded must mean a main path that works")
	case st == StateUnavailable && len(installs) > 0:
		t.Errorf("php unavailable although discovery found %v", php.Versions(installs))
	}
	if r := caps.Reason(FeatPHP); strings.TrimSpace(r) == "" {
		t.Error("php carries no reason, so the UI would have to invent one")
	} else if len(installs) > 0 && caps.State(FeatPHP) == StateDegraded &&
		!strings.Contains(r, caps.PHPVersions[0]) {
		t.Errorf("degraded reason %q does not name the version that was detected", r)
	}
}

// TestDetectPHPExtInstallFromEvidence pins the two mechanisms that used to be
// appended on faith. It reads the same host facts the implementation reads, so a
// future hardcode fails here on any box where the fact is false.
func TestDetectPHPExtInstallFromEvidence(t *testing.T) {
	caps, err := Current().Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	var want []ExtensionInstallMode
	if caps.PackageManager != "none" {
		want = append(want, ExtFromPackage)
	}
	if have("phpize") != "" {
		want = append(want, ExtFromSource)
	}
	got := caps.PHPExtInstall
	if len(got) != len(want) {
		t.Fatalf("php_ext_install = %v, host offers %v (package manager %q, phpize %q)",
			got, want, caps.PackageManager, have("phpize"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("php_ext_install[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// The mechanism is still not the feature: php_ext_source ships in M2.
	if caps.State(FeatPHPSourceExt) == StateAvailable {
		t.Error("php_ext_source available: no extension install code has been written yet")
	}
}

// TestDetectPHPFromRootedHosts runs detection against three fake hosts, which is
// the only way the evidence-based branch gets covered on a machine that does not
// have every PHP shape.
func TestDetectPHPFromRootedHosts(t *testing.T) {
	cases := []struct {
		name         string
		dirs         []string
		files        []string
		wantState    FeatureState
		wantModes    []PHPRuntimeMode
		wantInReason string
	}{
		{
			name:      "no php at all",
			wantState: StateUnavailable,
		},
		{
			// This dev host: cli present, fpm absent → the mode list must be empty
			// and the reason must say the backend is missing.
			name:         "cli only",
			dirs:         []string{"/etc/php/8.3/cli"},
			files:        []string{"/usr/bin/php8.3"},
			wantState:    StateDegraded,
			wantModes:    []PHPRuntimeMode{},
			wantInReason: "8.3",
		},
		{
			name:         "fpm installed",
			dirs:         []string{"/etc/php/8.3/cli", "/etc/php/8.3/fpm/pool.d"},
			files:        []string{"/usr/bin/php8.3", "/usr/sbin/php-fpm8.3"},
			wantState:    StateDegraded,
			wantModes:    []PHPRuntimeMode{PHPModeFPM},
			wantInReason: "fpm",
		},
		{
			name:         "cgi only",
			dirs:         []string{"/etc/php/8.3/cli", "/etc/php/8.3/cgi"},
			files:        []string{"/usr/bin/php8.3", "/usr/bin/php-cgi8.3"},
			wantState:    StateDegraded,
			wantModes:    []PHPRuntimeMode{PHPModeCGI},
			wantInReason: "cgi",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tc.files {
				full := filepath.Join(root, f)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("MINI_PANEL_ROOT", root)

			caps, err := Current().Detect()
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if st := caps.State(FeatPHP); st != tc.wantState {
				t.Errorf("php state = %q, want %q (reason %q)", st, tc.wantState, caps.Reason(FeatPHP))
			}
			got := caps.PHPModes
			if len(got) != len(tc.wantModes) {
				t.Fatalf("php_modes = %v, want %v", got, tc.wantModes)
			}
			for i := range tc.wantModes {
				if got[i] != tc.wantModes[i] {
					t.Errorf("php_modes[%d] = %q, want %q", i, got[i], tc.wantModes[i])
				}
			}
			if tc.wantInReason != "" && !strings.Contains(caps.Reason(FeatPHP), tc.wantInReason) {
				t.Errorf("reason %q does not name %q", caps.Reason(FeatPHP), tc.wantInReason)
			}
			// A fake root has no running fpm, so the reason must still name the
			// write path that has not shipped instead of implying it works.
			if len(caps.PHPModes) > 0 && !strings.Contains(caps.Reason(FeatPHP), "M2 交付") {
				t.Errorf("reason %q claims a handler without saying what is missing", caps.Reason(FeatPHP))
			}
		})
	}
}

// TestPHPCtlPathsAreTargetsAndStatesAreReads pins the split doctor's PHP line
// depends on: PHPCtl names where a backend lives, and the php package says
// whether it is there at this instant. The first must not move when the second
// does — if PoolDir went blank the moment the directory disappeared, the write
// side would have no way to ask "where does this pool go" about a pool it has
// not created yet, which is the whole call M2 has to make.
func TestPHPCtlPathsAreTargetsAndStatesAreReads(t *testing.T) {
	root := t.TempDir()
	dirs := []string{"/etc/php/8.3/cli", "/etc/php/8.3/fpm/pool.d", "/run/php"}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"/usr/bin/php8.3", "/usr/sbin/php-fpm8.3"} {
		full := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MINI_PANEL_ROOT", root)

	ctl, ok := Current().(PHPCtl)
	if !ok {
		t.Fatal("this platform does not implement PHPCtl, so there is nothing to pin")
	}
	pool, sock := ctl.PoolDir("8.3"), ctl.SocketPath("8.3")
	if want := filepath.Join(root, "/etc/php/8.3/fpm/pool.d"); pool != want {
		t.Errorf("PoolDir = %q, want %q", pool, want)
	}
	if got := php.DirStatus(pool); got != php.DirPresent {
		t.Errorf("DirStatus(%q) = %q, want present — the fixture just made it", pool, got)
	}
	// A rooted fixture has no running php-fpm, so the socket path exists as a
	// name and nothing more.
	if got := php.SocketStatus(sock); got != php.SocketAbsent {
		t.Errorf("SocketStatus(%q) = %q, want absent", sock, got)
	}

	if err := os.RemoveAll(pool); err != nil {
		t.Fatal(err)
	}
	if again := ctl.PoolDir("8.3"); again != pool {
		t.Errorf("PoolDir changed from %q to %q when the directory went away; the target is a calculation, not an ls", pool, again)
	}
	if got := php.DirStatus(pool); got != php.DirAbsent {
		t.Errorf("DirStatus after RemoveAll = %q, want absent — this is the read that had to change", got)
	}
}
