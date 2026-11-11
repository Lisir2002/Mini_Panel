package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Basic Auth is a fixed server-level gate with its own password file. These
// tests pin the hash format and file mode, the exact directives, the marker
// round-trip, the ACME challenge exemption, the one-unit rollback of config and
// password file, and the validation matrix.

func TestSetAuthWritesHtpasswdAndRenders(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetAuth("old", "guest", "Sup3rSecret!")
	if err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if site.AuthUser != "guest" {
		t.Errorf("returned auth user = %q", site.AuthUser)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	path := authPath(m.AuthDir, "old")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat htpasswd: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("htpasswd mode = %o, want 600", perm)
	}
	if perm := mustStat(t, m.AuthDir).Mode().Perm(); perm != 0o700 {
		t.Errorf("auth dir mode = %o, want 700", perm)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read htpasswd: %v", err)
	}
	wantLine := "guest:" + authHash("Sup3rSecret!") + "\n"
	if string(body) != wantLine {
		t.Errorf("htpasswd = %q, want %q", body, wantLine)
	}
	if !strings.HasPrefix(authHash("Sup3rSecret!"), "{SHA}") {
		t.Errorf("hash = %q, want a {SHA} prefix nginx accepts", authHash("Sup3rSecret!"))
	}
	if strings.Contains(string(body), "Sup3rSecret!") {
		t.Error("htpasswd contains the plaintext password")
	}

	conf, err := os.ReadFile(m.Layout.ConfigPath("old"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		`auth_basic "Mini Panel";`,
		"auth_basic_user_file " + path + ";",
		`"auth_user":"guest"`,
		"location / {",
		"try_files $uri $uri/ =404;",
	} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("auth config missing %q\n%s", want, conf)
		}
	}
	if strings.Contains(string(conf), "Sup3rSecret!") || strings.Contains(string(conf), authHash("Sup3rSecret!")) {
		t.Errorf("vhost contains the password or its hash\n%s", conf)
	}
	if strings.Contains(string(conf), "acme-challenge") {
		t.Errorf("plain HTTP site got a challenge exemption it does not need\n%s", conf)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].AuthUser != "guest" || list[0].AuthFile != path {
		t.Errorf("marker round-trip auth = %q / %q", list[0].AuthUser, list[0].AuthFile)
	}

	// Auth is server-level, so it does not collide with a reverse proxy that
	// owns location /. The gate stays in place while the proxy block changes.
	if _, err := m.SetProxy("old", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy with auth enabled: %v", err)
	}
	conf, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if !strings.Contains(string(conf), `auth_basic "Mini Panel";`) || !strings.Contains(string(conf), "proxy_pass http://127.0.0.1:3000") {
		t.Errorf("auth and proxy did not coexist\n%s", conf)
	}

	if _, err := m.SetAuth("old", "", ""); err != nil {
		t.Fatalf("clear auth: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("clearing auth left the password file: %v", err)
	}
	conf, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if strings.Contains(string(conf), "auth_basic") || strings.Contains(string(conf), `"auth_user"`) {
		t.Errorf("clearing auth left directives or marker state\n%s", conf)
	}
	list, _ = m.List()
	if len(list) != 1 || list[0].AuthUser != "" {
		t.Errorf("marker after clearing auth = %+v", list)
	}
}

func TestAuthKeepsACMEChallengeOpen(t *testing.T) {
	site := Site{
		Name: "old", Domains: []string{"old.example.com"}, Root: "/srv/old",
		AuthUser: "guest", AuthFile: "/etc/minipanel/auth/minipanel-old.htpasswd",
		TLS: &TLSInfo{
			Enabled: true, CertPath: "/etc/minipanel/certs/old.crt", KeyPath: "/etc/minipanel/certs/old.key",
		},
	}
	out := render(site)
	if !strings.Contains(out, `auth_basic "Mini Panel";`) {
		t.Fatalf("auth site has no auth_basic\n%s", out)
	}
	idx := strings.Index(out, "location ^~ /.well-known/acme-challenge/ {")
	if idx < 0 {
		t.Fatalf("TLS auth site has no ACME challenge exemption\n%s", out)
	}
	block := out[idx:]
	if end := strings.Index(block, "}"); end < 0 || !strings.Contains(block[:end], "auth_basic off;") {
		t.Errorf("challenge location does not disable auth\n%s", block[:120])
	}
	if strings.Index(out, "location / {") < idx {
		t.Errorf("challenge exemption must be rendered before location /\n%s", out)
	}

	// Redirect mode: the port-80 block only redirects but already carries the
	// challenge exemption, so renewal works there too.
	redir := render(Site{
		Name: "old", Domains: []string{"old.example.com"}, Root: "/srv/old",
		AuthUser: "guest", AuthFile: "/etc/minipanel/auth/minipanel-old.htpasswd",
		TLS: &TLSInfo{
			Enabled: true, Redirect: true, CertPath: "/etc/minipanel/certs/old.crt", KeyPath: "/etc/minipanel/certs/old.key",
		},
	})
	second := strings.LastIndex(redir, "server {")
	if second <= 0 {
		t.Fatalf("redirect render has no second server block\n%s", redir)
	}
	port80 := redir[:second]
	if !strings.Contains(port80, "acme-challenge") || strings.Contains(port80, "auth_basic") {
		t.Errorf("port-80 block should keep challenges public and add no auth\n%s", port80)
	}
	if !strings.Contains(redir[second:], "auth_basic_user_file") {
		t.Errorf("https block does not carry the auth directives\n%s", redir[second:])
	}
}

func TestSetAuthRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetAuth("old", "guest", "Sup3rSecret!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	confBefore, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	fileBefore, _ := os.ReadFile(authPath(m.AuthDir, "old"))

	rec.failOn = "-t"
	if _, err := m.SetAuth("old", "guest2", "AnotherSecret!"); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetAuth err = %v, want ErrConfigRejected", err)
	}
	confAfter, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	fileAfter, _ := os.ReadFile(authPath(m.AuthDir, "old"))
	if string(confAfter) != string(confBefore) {
		t.Errorf("failed auth change was not rolled back\nbefore:\n%s\nafter:\n%s", confBefore, confAfter)
	}
	if string(fileAfter) != string(fileBefore) {
		t.Errorf("failed auth change left a new password file\nbefore: %q\nafter: %q", fileBefore, fileAfter)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].AuthUser != "guest" {
		t.Errorf("marker after rollback = %+v", list)
	}

	// A password-only change rewrites the hash but not the vhost, so it needs no
	// reload and cannot be blocked by a broken nginx test.
	rec.failOn = ""
	rec.cmds = nil
	if _, err := m.SetAuth("old", "guest", "RotatedSecret!"); err != nil {
		t.Fatalf("rotate password: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("password-only change ran nginx commands: %v", rec.cmds)
	}
	rotated, _ := os.ReadFile(authPath(m.AuthDir, "old"))
	if string(rotated) == string(fileBefore) {
		t.Error("password-only change did not rewrite the hash")
	}

	// First-time enable failure must not leave a password file behind.
	if _, err := m.SetAuth("old", "", ""); err != nil {
		t.Fatalf("clear auth: %v", err)
	}
	rec.failOn = "-t"
	if _, err := m.SetAuth("old", "guest", "Sup3rSecret!"); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("first enable failure err = %v", err)
	}
	if _, err := os.Stat(authPath(m.AuthDir, "old")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed first enable left a password file: %v", err)
	}
}

func TestAuthIsValidated(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	cases := []struct{ user, pass string }{
		{"bad:name", "Sup3rSecret!"},
		{"bad/name", "Sup3rSecret!"},
		{"-leading", "Sup3rSecret!"},
		{"", "Sup3rSecret!"},
		{"guest", ""},
		{"guest", "short"},
		{"guest", "with\nnewline!"},
	}
	for _, c := range cases {
		if _, err := m.SetAuth("old", c.user, c.pass); !errors.Is(err, ErrInvalid) {
			t.Errorf("SetAuth(%q, %q) err = %v, want ErrInvalid", c.user, c.pass, err)
		}
	}
	if len(rec.cmds) != 0 {
		t.Errorf("validation ran nginx commands: %v", rec.cmds)
	}
	if _, err := os.Stat(authPath(m.AuthDir, "old")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rejected input wrote a password file: %v", err)
	}
	// Clearing an unset gate is a no-op, not an error or a reload.
	if _, err := m.SetAuth("old", "", ""); err != nil {
		t.Errorf("clear unset auth: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("clearing unset auth ran nginx commands: %v", rec.cmds)
	}
}

func TestMarkerRejectsBadAuthUser(t *testing.T) {
	markers := []string{
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","auth_user":"bad:name"}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","auth_user":"with space"}`,
	}
	for _, marker := range markers {
		m, _ := newTestManager(t)
		body := headerLine + "\n" + markerLine + marker + "\n"
		if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("old")), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		list, err := m.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Errorf("invalid auth marker listed as a panel site: %s", marker)
		}
	}

	m, _ := newTestManager(t)
	body := headerLine + "\n" + markerLine +
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","auth_user":"guest"}` + "\n"
	if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("old")), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].AuthUser != "guest" {
		t.Errorf("valid auth marker not read: %+v", list[0])
	}
	if list[0].AuthFile != authPath(m.AuthDir, "old") {
		t.Errorf("auth file path = %q", list[0].AuthFile)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st
}
