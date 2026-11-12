//go:build linux

package nginx

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

// The ownership guarantee is Linux-specific because the site provider itself
// is only offered on Linux; the assertion needs the platform's stat uid.
func TestEnsureLogDirOwnedByNginxUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership adjustment only happens when the panel runs as root")
	}
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	u, err := user.Lookup(nginxUser(m.Layout.ConfigDir))
	if err != nil {
		t.Fatalf("lookup nginx user: %v", err)
	}
	wantUID, _ := strconv.Atoi(u.Uid)
	fi, err := os.Stat(m.LogDir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat uid on linux")
	}
	if int(st.Uid) != wantUID {
		t.Errorf("log dir uid = %d, want nginx user %s (%d)", st.Uid, u.Username, wantUID)
	}
}
