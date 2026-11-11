package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	Socket      string   `json:"php_socket"`
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
	// Paths are reported as paths. Nothing here may claim the socket is alive.
	if !strings.HasSuffix(d.PoolDir, "/etc/php/8.3/fpm/pool.d") || !strings.HasSuffix(d.Socket, "/run/php/php8.3-fpm.sock") {
		t.Errorf("pool=%q socket=%q, want the rooted Debian layout", d.PoolDir, d.Socket)
	}

	plain, err := captureStdout(t, func() error { return dispatch([]string{"doctor"}) })
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	line := labelled(t, plain, "PHP")
	for _, want := range []string{"8.3", "pool", "socket", "未校验 socket 是否存活"} {
		if !strings.Contains(line, want) {
			t.Errorf("PHP line %q lacks %q", line, want)
		}
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
