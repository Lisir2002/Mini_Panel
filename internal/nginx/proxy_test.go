package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reverse proxy is a fixed directive block around one validated upstream URL.
// These tests pin the security boundary (only scheme/host/port/path reach the
// config), the mutual exclusion with rewrite templates, and the same
// test-before-reload protocol as every other vhost write.

func TestProxyTargetValidation(t *testing.T) {
	valid := map[string]string{
		"http://127.0.0.1:3000":     "http://127.0.0.1:3000",
		"HTTPS://App.Example.COM":   "https://app.example.com",
		"http://[::1]:8080/api/":    "http://[::1]:8080/api/",
		"http://localhost":          "http://localhost",
		"http://example.com:65535":  "http://example.com:65535",
		"http://example.com:08080":  "http://example.com:8080",
		"http://example.com/a%20b":  "http://example.com/a%20b",
		"http://example.com/api/v1": "http://example.com/api/v1",
	}
	for in, want := range valid {
		got, ws, err := normalizeProxy(in, false)
		if err != nil {
			t.Errorf("normalizeProxy(%q) error: %v", in, err)
			continue
		}
		if got != want || ws {
			t.Errorf("normalizeProxy(%q) = %q, %v; want %q, false", in, got, ws, want)
		}
	}
	if got, ws, err := normalizeProxy("  http://127.0.0.1:3000  ", true); err != nil || got != "http://127.0.0.1:3000" || !ws {
		t.Errorf("trim/websocket = %q, %v, %v", got, ws, err)
	}

	invalid := []string{
		"ftp://example.com",
		"example.com:3000",
		"http://",
		"http://user:pass@example.com",
		"http://example.com/path?x=1",
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
		"http://example.com/\u4e2d\u6587",
		"http://[::1",
		strings.Repeat("a", maxUpstreamTarget+1),
	}
	for _, in := range invalid {
		if _, _, err := normalizeProxy(in, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeProxy(%q) err = %v, want ErrInvalid", in, err)
		}
	}
	if _, _, err := normalizeProxy("", true); !errors.Is(err, ErrInvalid) {
		t.Errorf("websocket without target err = %v, want ErrInvalid", err)
	}
}

func TestProxyRendersAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetProxy("app", "HTTP://127.0.0.1:3000", true)
	if err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if site.ProxyTarget != "http://127.0.0.1:3000" || !site.ProxyWebSocket {
		t.Errorf("returned proxy = %q, %v", site.ProxyTarget, site.ProxyWebSocket)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("app"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		"proxy_pass http://127.0.0.1:3000;",
		"proxy_http_version 1.1;",
		"proxy_set_header Host $host;",
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
		"proxy_set_header Upgrade $http_upgrade;",
		`proxy_set_header Connection "upgrade";`,
		`"proxy_target":"http://127.0.0.1:3000"`,
		`"proxy_websocket":true`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("proxy config missing %q\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "try_files $uri $uri/ =404;") {
		t.Errorf("proxied site still renders the static fallback\n%s", body)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].ProxyTarget != "http://127.0.0.1:3000" || !list[0].ProxyWebSocket {
		t.Errorf("marker round-trip proxy = %+v", list[0])
	}

	if _, err := m.SetProxy("app", "", false); err != nil {
		t.Fatalf("clear proxy: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("app"))
	if !strings.Contains(string(body), "try_files $uri $uri/ =404;") {
		t.Errorf("cleared proxy did not restore the static fallback\n%s", body)
	}
	if strings.Contains(string(body), "proxy_pass") {
		t.Errorf("cleared proxy left proxy_pass behind\n%s", body)
	}
}

func TestProxyAndRewriteAreMutuallyExclusive(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"}, Rewrite: "spa",
	}); err != nil {
		t.Fatalf("Create SPA: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if _, err := m.SetProxy("blog", "http://127.0.0.1:3000", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("proxy over spa rewrite err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("rejected proxy changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}

	if _, err := m.SetRewrite("blog", "none"); err != nil {
		t.Fatalf("reset rewrite: %v", err)
	}
	if _, err := m.SetProxy("blog", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	before, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if _, err := m.SetRewrite("blog", "spa"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rewrite over proxy err = %v, want ErrInvalid", err)
	}
	after, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("rejected rewrite changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}

	if _, err := m.SetProxy("blog", "", false); err != nil {
		t.Fatalf("clear proxy: %v", err)
	}
	if _, err := m.SetRewrite("blog", "spa"); err != nil {
		t.Fatalf("rewrite after clearing proxy: %v", err)
	}
}

func TestSetProxyRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	rec.failOn = "-t"
	if _, err := m.SetProxy("app", "http://127.0.0.1:4000", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetProxy err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if string(after) != string(before) {
		t.Errorf("failed proxy change was not rolled back\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].ProxyTarget != "http://127.0.0.1:3000" {
		t.Errorf("marker after rollback = %+v", list)
	}
}

func TestMarkerRejectsInvalidProxy(t *testing.T) {
	cases := []string{
		`{"name":"app","domains":["app.example.com"],"root":"/tmp/app","created_at":"2026-01-01T00:00:00Z","proxy_target":"http://127.0.0.1:3000;evil"}`,
		`{"name":"app","domains":["app.example.com"],"root":"/tmp/app","created_at":"2026-01-01T00:00:00Z","rewrite":"spa","proxy_target":"http://127.0.0.1:3000"}`,
		`{"name":"app","domains":["app.example.com"],"root":"/tmp/app","created_at":"2026-01-01T00:00:00Z","proxy_websocket":true}`,
	}
	for _, marker := range cases {
		m, _ := newTestManager(t)
		body := headerLine + "\n" + markerLine + marker + "\n"
		if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("app")), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		list, err := m.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Errorf("invalid proxy marker listed as a panel site: %s", marker)
		}
	}
}
