package platform

import (
	"runtime"
	"strings"
	"testing"
)

// TestCapabilityStatesAreSymmetric covers the four-state contract
// (docs/功能设计.md §4.1). The two things a caller must never be able to produce
// are an unexplained refusal and an "available" entry still dragging a fix
// action from an earlier state — both are how a UI ends up rendering a control
// that lies.
func TestCapabilityStatesAreSymmetric(t *testing.T) {
	c := newBase()
	if c.Has(FeatWebSite) {
		t.Fatal("newBase must deny write features")
	}
	if got := c.State(FeatWebSite); got != StateUnavailable {
		t.Fatalf("newBase state for %s = %q, want unavailable", FeatWebSite, got)
	}

	c.Allow(FeatWebSite)
	if !c.Has(FeatWebSite) {
		t.Fatal("Allow did not take effect")
	}
	f := c.Features[FeatWebSite]
	if f.Reason != "" || f.FixAction != "" || f.Verify != "" {
		t.Fatalf("Allow left stale explanation behind: %+v", f)
	}

	c.Deny(FeatWebSite, "not here")
	if c.Has(FeatWebSite) {
		t.Fatal("Deny did not take effect")
	}
	if c.Reason(FeatWebSite) != "not here" {
		t.Fatalf("Deny dropped its reason: %q", c.Reason(FeatWebSite))
	}

	// An empty reason is the bug the whole contract exists to prevent, so it is
	// refused at the data structure and becomes a self-reporting sentence.
	c.Deny(FeatWebSite, "   ")
	if c.Has(FeatWebSite) {
		t.Fatal("Deny with an empty reason still disabled")
	}
	if strings.TrimSpace(c.Reason(FeatWebSite)) == "" {
		t.Fatal("empty reason stored verbatim; the UI would have to invent text")
	}

	// Degraded is reachable-but-short, so it must not read as available: a
	// handler that gates on Has() refuses the click rather than half-doing it.
	c.Degrade(FeatMonitor, "采样可用，图表在 M4 交付", "minipanel doctor", "/api/v1/system/info")
	if c.Has(FeatMonitor) {
		t.Fatal("degraded must not report as available")
	}
	d := c.Features[FeatMonitor]
	if d.State != StateDegraded || d.FixAction == "" || d.Verify == "" {
		t.Fatalf("Degrade lost a field: %+v", d)
	}

	// Foreign objects are readable but not ours to write.
	c.Foreign(FeatFilePerms, "该文件由 Docker 卷挂载，属主不在面板名下")
	if c.Has(FeatFilePerms) || c.State(FeatFilePerms) != StateForeign {
		t.Fatalf("Foreign did not take effect: %+v", c.Features[FeatFilePerms])
	}

	// Denying an unknown key must not panic: feature names come from a list the
	// front end reads, and a typo there should be loud, not fatal.
	c.Deny("made_up_feature", "reason")
	if !strings.Contains(c.Reason("made_up_feature"), "reason") {
		t.Error("reason for an unknown feature was dropped")
	}
	// Reading a key nobody declared is also not fatal, and answers the honest
	// default: not available.
	if c.State("never_declared") != StateUnavailable || c.Has("never_declared") {
		t.Error("undeclared feature read back as something other than unavailable")
	}
}

// declaredFeatures is the registry side of the contract: every key the panel
// knows about, so a denial list can quietly drop one and the test catches it.
// Adding a key here is the §4.3 approval step — semantics, read or write, the
// Linux and Windows path, what decides the state, and the test that pins it.
func declaredFeatures() []string {
	return []string{
		FeatWebSite, featSiteWrite, FeatPHP, featPHPVersionSwitch, FeatPHPSourceExt,
		FeatSSL, FeatDatabase, FeatBackup, FeatFirewall, featFirewallWrite,
		featServiceWrite, FeatCron, FeatTerminal, FeatMonitor, FeatAudit,
		FeatSSHManager, FeatFilePerms,
	}
}

// declaredKey is the reverse direction: php_fpm only exists on Windows, so the
// set of legal keys is "everything the panel declares", not "everything this
// OS happens to report".
func declaredKey(name string) bool {
	for _, k := range declaredFeatures() {
		if k == name {
			return true
		}
	}
	return false
}

// TestDetectedCapabilitiesAreExplained is the contract the UI is allowed to rely
// on: any feature not reported available must carry a reason an operator can
// read, and every reason-carrying entry must be one the panel declared.
// A missing reason is what forces a front end to either hide the control or
// render a dead button — the two BaoTa variants we refuse to copy.
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

	legal := map[FeatureState]bool{
		StateAvailable: true, StateDegraded: true, StateUnavailable: true, StateForeign: true,
	}
	for name, f := range c.Features {
		if !legal[f.State] {
			t.Errorf("feature %q has state %q, which is not one of the four", name, f.State)
			continue
		}
		if f.State == StateAvailable {
			if f.Reason != "" {
				t.Errorf("available feature %q carries a reason %q", name, f.Reason)
			}
			continue
		}
		if strings.TrimSpace(f.Reason) == "" {
			t.Errorf("feature %q is %s without a reason", name, f.State)
		}
		if strings.Contains(f.Reason, noReasonStored) {
			t.Errorf("feature %q fell back to the missing-reason placeholder: the detect path never explained it", name)
		}
	}
	// A key the front end has never heard of is the other way to ship a control
	// that does nothing: it would be rendered from a hardcoded list and silently
	// miss whatever Detect() started reporting.
	for name := range c.Features {
		if !declaredKey(name) {
			t.Errorf("bitmap reports undeclared feature %q; docs/功能设计.md §4.3 is the approval step this is missing", name)
		}
	}
	// The other direction: a declared key must be present, or the UI renders it
	// as "never heard of it", which is the hiding this contract forbids.
	for _, name := range declaredFeatures() {
		if _, ok := c.Features[name]; !ok {
			t.Errorf("declared feature %q missing from the bitmap", name)
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
	//
	// Two kinds of entry. `implemented` is unconditional: the code is in this
	// binary and works on every host it runs on. `conditional` is for modules
	// whose availability is a fact about the host (nginx installed, process is
	// root) — and the predicate asks the platform implementation itself rather
	// than re-deriving that fact here, so the bitmap and the writer cannot
	// disagree about whether a site can be created. Both directions are
	// enforced: an available key in neither map fails, and a conditional key
	// whose predicate holds but which is not available fails too.
	implemented := map[string]bool{FeatAudit: true}
	conditional := map[string]func(*Capabilities) bool{
		FeatWebSite:   siteWriterReady,
		featSiteWrite: siteWriterReady,
		FeatSSL:       siteTLSReady,
	}
	for name, f := range c.Features {
		if f.State != StateAvailable {
			continue
		}
		if implemented[name] {
			continue
		}
		if pred, ok := conditional[name]; ok && pred(c) {
			continue
		}
		t.Errorf("这一版把 %s 报成可用，但没有对应实现", name)
	}
	for name := range implemented {
		if !c.Has(name) {
			t.Errorf("%s 是本版已实现的能力，必须报为可用", name)
		}
	}
	for name, pred := range conditional {
		if !pred(c) {
			continue
		}
		if !c.Has(name) {
			t.Errorf("%s 的前置条件已满足，但位图没有把它报成可用", name)
		}
	}
}

// siteWriterReady is the whitelist predicate for the M2 site slice: it asks the
// platform whether a SiteManager is actually reachable right now, which is the
// same question Detect() answers for the bitmap (nginx layout present, process
// can write). Keeping one implementation means a host where the writer says
// "no" can never be reported as site-available, and vice versa.
func siteWriterReady(*Capabilities) bool {
	sp, ok := Current().(SiteProvider)
	if !ok {
		return false
	}
	m, ok := sp.Sites()
	return ok && m != nil
}

// siteTLSReady requires the optional ACME interface as well as the base site
// writer: ssl is advertised as available only when all three certificate paths
// (self-signed, upload, ACME HTTP-01) are reachable on this host. A provider that
// implements only manual TLS is a legitimate build, and its ssl must stay
// degraded rather than claiming automatic renewal the binary cannot do.
func siteTLSReady(*Capabilities) bool {
	sp, ok := Current().(SiteProvider)
	if !ok {
		return false
	}
	m, ok := sp.Sites()
	if !ok || m == nil {
		return false
	}
	_, ok = m.(SiteACMEManager)
	return ok
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
