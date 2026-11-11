package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Site-wide redirect is a fixed `return` line around one validated URL. These
// tests pin the URL/status validation, the exact rendering (including
// $request_uri), the three-way exclusion with rewrite and proxy, rollback, and
// the marker round-trip.

func TestRedirectTargetValidation(t *testing.T) {
	valid := []struct {
		in       string
		code     int
		keepPath bool
		want     string
	}{
		{"https://new.example.com", 301, true, "https://new.example.com"},
		{" HTTPS://New.Example.COM/ ", 302, false, "https://new.example.com/"},
		{"http://127.0.0.1:8080/base/", 301, true, "http://127.0.0.1:8080/base"},
		{"https://example.com/path", 302, false, "https://example.com/path"},
	}
	for _, c := range valid {
		got, code, keep, err := normalizeRedirect(c.in, c.code, c.keepPath)
		if err != nil {
			t.Errorf("normalizeRedirect(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want || code != c.code || keep != c.keepPath {
			t.Errorf("normalizeRedirect(%q) = %q, %d, %v; want %q, %d, %v",
				c.in, got, code, keep, c.want, c.code, c.keepPath)
		}
	}

	if got, code, keep, err := normalizeRedirect("", 999, true); err != nil || got != "" || code != 0 || keep {
		t.Errorf("empty target clear = %q, %d, %v, %v; want zero values, nil", got, code, keep, err)
	}

	invalidTargets := []string{
		"ftp://example.com",
		"example.com",
		"http://",
		"http://user:pass@example.com",
		"http://example.com/a?x=1",
		"http://example.com/#frag",
		"http://example.com:0",
		"http://example.com:70000",
		"http://exa mple.com",
		"http://example.com/a;b",
		"http://example.com/$x",
		"http://example.com/{x}",
		"http://example.com/a\"b",
		"http://example.com/a\nb",
		"http://-bad.example.com",
		"http://bad..example.com",
		"http://example.com/..",
		"http://example.com/a/%2e%2e/b",
		"http://[::1",
	}
	for _, in := range invalidTargets {
		if _, _, _, err := normalizeRedirect(in, 301, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeRedirect(%q) err = %v, want ErrInvalid", in, err)
		}
	}
	for _, code := range []int{0, 200, 303, 307, 308, 404} {
		if _, _, _, err := normalizeRedirect("https://new.example.com", code, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeRedirect code %d err = %v, want ErrInvalid", code, err)
		}
	}
}

func TestRedirectRendersAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetRedirect("old", "HTTPS://New.Example.COM/", 301, true)
	if err != nil {
		t.Fatalf("SetRedirect: %v", err)
	}
	if site.RedirectTarget != "https://new.example.com" || site.RedirectCode != 301 || !site.RedirectKeepPath {
		t.Errorf("returned redirect = %q, %d, %v", site.RedirectTarget, site.RedirectCode, site.RedirectKeepPath)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("old"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		"return 301 https://new.example.com$request_uri;",
		`"redirect_target":"https://new.example.com"`,
		`"redirect_code":301`,
		`"redirect_keep_path":true`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("redirect config missing %q\n%s", want, body)
		}
	}
	for _, unwanted := range []string{"try_files $uri $uri/ =404;", "proxy_pass"} {
		if strings.Contains(string(body), unwanted) {
			t.Errorf("redirecting site still renders %q\n%s", unwanted, body)
		}
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].RedirectTarget != "https://new.example.com" ||
		list[0].RedirectCode != 301 || !list[0].RedirectKeepPath {
		t.Errorf("marker round-trip redirect = %+v", list[0])
	}

	if _, err := m.SetRedirect("old", "https://new.example.com/base/", 302, false); err != nil {
		t.Fatalf("replace redirect: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if !strings.Contains(string(body), "return 302 https://new.example.com/base/;") {
		t.Errorf("replaced redirect not rendered exactly\n%s", body)
	}

	if _, err := m.SetRedirect("old", "", 0, false); err != nil {
		t.Fatalf("clear redirect: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if !strings.Contains(string(body), "try_files $uri $uri/ =404;") {
		t.Errorf("cleared redirect did not restore the static fallback\n%s", body)
	}
	if strings.Contains(string(body), "return 30") {
		t.Errorf("cleared redirect left a return line behind\n%s", body)
	}
}

func TestRedirectExcludesRewriteAndProxy(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"}, Rewrite: "spa",
	}); err != nil {
		t.Fatalf("Create SPA: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if _, err := m.SetRedirect("blog", "https://new.example.com", 301, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("redirect over spa rewrite err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("rejected redirect changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}

	if _, err := m.SetRewrite("blog", "none"); err != nil {
		t.Fatalf("reset rewrite: %v", err)
	}
	if _, err := m.SetRedirect("blog", "https://new.example.com", 301, true); err != nil {
		t.Fatalf("SetRedirect: %v", err)
	}
	before, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if _, err := m.SetRewrite("blog", "spa"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rewrite over redirect err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetProxy("blog", "http://127.0.0.1:3000", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("proxy over redirect err = %v, want ErrInvalid", err)
	}
	after, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("rejected rewrite/proxy changed the redirect config\nbefore:\n%s\nafter:\n%s", before, after)
	}

	if _, err := m.SetRedirect("blog", "", 0, false); err != nil {
		t.Fatalf("clear redirect: %v", err)
	}
	if _, err := m.SetProxy("blog", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("proxy after clearing redirect: %v", err)
	}
	before, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if _, err := m.SetRedirect("blog", "https://new.example.com", 301, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("redirect over proxy err = %v, want ErrInvalid", err)
	}
	after, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("rejected redirect changed the proxy config\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestSetRedirectRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetRedirect("old", "https://new.example.com", 301, true); err != nil {
		t.Fatalf("SetRedirect: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	rec.failOn = "-t"
	if _, err := m.SetRedirect("old", "https://other.example.com", 302, false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetRedirect err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("failed redirect change was not rolled back\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].RedirectTarget != "https://new.example.com" {
		t.Errorf("marker after rollback = %+v", list)
	}
}

func TestMarkerRejectsInvalidRedirect(t *testing.T) {
	cases := []string{
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_target":"https://new.example.com;evil","redirect_code":301}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_target":"https://new.example.com","redirect_code":307}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_target":"https://new.example.com","redirect_code":301,"rewrite":"spa"}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_target":"https://new.example.com","redirect_code":301,"proxy_target":"http://127.0.0.1:3000"}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_target":"https://new.example.com"}`,
	}
	for _, marker := range cases {
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
			t.Errorf("invalid redirect marker listed as a panel site: %s", marker)
		}
	}
}
