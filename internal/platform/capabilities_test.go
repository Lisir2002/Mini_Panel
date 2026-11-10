package platform

import (
	"runtime"
	"strings"
	"testing"
)

func TestDenyAndAllowAreSymmetric(t *testing.T) {
	c := newBase()
	if c.Has(FeatWebSite) {
		t.Fatal("newBase must deny write features")
	}
	c.Allow(FeatWebSite)
	if !c.Has(FeatWebSite) {
		t.Fatal("Allow did not take effect")
	}
	if r := c.Unavailable[FeatWebSite]; r != "" {
		t.Fatalf("Allow left a stale reason behind: %q", r)
	}
	c.Deny(FeatWebSite, "not here")
	if c.Has(FeatWebSite) {
		t.Fatal("Deny did not take effect")
	}
	c.Deny(FeatWebSite, "")
	if c.Has(FeatWebSite) {
		t.Fatal("Deny with an empty reason still disabled")
	}
	// Denying an unknown key must not panic: feature names come from a list the
	// front end reads, and a typo there should be loud, not fatal.
	c.Deny("made_up_feature", "reason")
	if !strings.Contains(c.Unavailable["made_up_feature"], "reason") {
		t.Error("reason for an unknown feature was dropped")
	}
}

// TestDetectedCapabilitiesAreExplained is the contract the UI is allowed to rely
// on: any feature reported as unavailable must carry a reason an operator can
// read. A missing reason is what forces a front end to either hide the control
// or render a dead button — the two BaoTa variants we refuse to copy.
func TestDetectedCapabilitiesAreExplained(t *testing.T) {
	c, err := Current().Detect()
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if c.OS != runtime.GOOS {
		t.Errorf("os = %s, want %s", c.OS, runtime.GOOS)
	}
	if c.Hostname == "" || c.Hostname == "unknown-host" {
		t.Logf("hostname detection fell back: %q", c.Hostname)
	}
	for name, on := range c.Features {
		if on {
			continue
		}
		if r := c.Unavailable[name]; strings.TrimSpace(r) == "" {
			t.Errorf("feature %q is off without a reason", name)
		}
	}
	// Identity fields must be populated even on a minimal container, or the
	// dashboard renders blanks.
	if len(c.Schedulers) == 0 {
		t.Error("schedulers empty: the panel scheduler is always available")
	}
	if c.Arch == "" {
		t.Error("arch empty")
	}
	// Nothing this build cannot do may be advertised. The list is a whitelist
	// rather than a blacklist: a feature only becomes legal here once the code
	// behind it exists on every platform the panel claims, which is what stops a
	// platform-specific `Allow` from sneaking a dead button into the UI.
	implemented := map[string]bool{FeatAudit: true}
	for name, on := range c.Features {
		if on && !implemented[name] {
			t.Errorf("M0 把 %s 报成可用，但这个版本里没有对应实现", name)
		}
	}
	for name := range implemented {
		if !c.Has(name) {
			t.Errorf("%s 是 M0 已实现的能力，必须报为可用", name)
		}
	}
}

func TestPathsAreAbsoluteAndConsistent(t *testing.T) {
	p := Current()
	for name, dir := range map[string]string{
		"config": p.ConfigDir(), "data": p.DataDir(), "log": p.LogDir(),
		"site": p.SiteRoot(), "backup": p.BackupRoot(),
	} {
		if dir == "" {
			t.Errorf("%s path is empty", name)
			continue
		}
		if !strings.HasPrefix(dir, "/") && !strings.Contains(dir, ":\\") && !strings.Contains(dir, string(rune(0))) {
			// On non-Windows builds with MINI_PANEL_ROOT unset the dev stub may
			// return a relative path; the real platforms must not.
			if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
				t.Errorf("%s path is not absolute: %q", name, dir)
			}
		}
	}
}
