//go:build linux

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolvePHPBindingChecksDiscoveryBeforeConfig pins the ordering the site
// handler depends on: a version that discovery did not prove to have fpm is
// rejected before any nginx file is touched. The alternative — accepting the
// version and letting nginx -t pass — writes a valid vhost pointing at a socket
// that cannot exist, which only shows up as a 502 after "success".
func TestResolvePHPBindingChecksDiscoveryBeforeConfig(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"/etc/php/8.1/cli", "/etc/php/8.2/cli", "/etc/php/8.2/fpm/pool.d", "/etc/php/8.3/cli", "/etc/php/8.3/fpm/pool.d"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		"/usr/bin/php8.1", "/usr/bin/php8.2", "/usr/bin/php8.3",
		"/usr/sbin/php-fpm8.2", "/usr/sbin/php-fpm8.3",
	} {
		full := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MINI_PANEL_ROOT", root)

	version, socket, err := resolvePHPBinding("8.3")
	if err != nil {
		t.Fatalf("resolve 8.3: %v", err)
	}
	wantSocket := filepath.Join(root, "/run/php/php8.3-fpm.sock")
	if version != "8.3" || socket != wantSocket {
		t.Errorf("binding = %q/%q, want 8.3/%q", version, socket, wantSocket)
	}

	for _, tc := range []struct{ version, want string }{
		{"8.1", "没有 fpm"},
		{"9.9", "没有检测到"},
	} {
		_, _, err := resolvePHPBinding(tc.version)
		if !errors.Is(err, ErrSitePHP) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("resolve %q err = %v, want ErrSitePHP with %q", tc.version, err, tc.want)
		}
	}

	version, socket, err = resolvePHPBinding("  ")
	if err != nil || version != "" || socket != "" {
		t.Errorf("empty binding = %q/%q/%v, want empty success", version, socket, err)
	}
}
