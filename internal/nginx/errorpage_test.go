package nginx

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Custom error pages are server-level error_page directives. These tests pin
// status/path validation, exact rendering, marker round-trips, coexistence
// with location / owners, rollback and marker rejection.

func TestErrorPagesAreValidated(t *testing.T) {
	got, err := normalizeErrorPages([]ErrorPageRule{
		{Code: 500, Path: "/50x.html"},
		{Code: 404, Path: " /404.html "},
	})
	if err != nil {
		t.Fatalf("normalizeErrorPages: %v", err)
	}
	want := []ErrorPageRule{{Code: 404, Path: "/404.html"}, {Code: 500, Path: "/50x.html"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("sorted/trimmed rules = %+v, want %+v", got, want)
	}

	if got, err := normalizeErrorPages(nil); err != nil || got != nil {
		t.Errorf("empty table clear = %v, %v", got, err)
	}

	invalid := [][]ErrorPageRule{
		{{Code: 200, Path: "/ok.html"}},
		{{Code: 301, Path: "/moved.html"}},
		{{Code: 404, Path: "404.html"}},
		{{Code: 404, Path: "/../secret.html"}},
		{{Code: 404, Path: "/404.html;return 500"}},
		{{Code: 404, Path: "/404.html?a=1"}},
		{{Code: 404, Path: "/err page.html"}},
		{{Code: 404, Path: "/.well-known/acme-challenge/token"}},
		{{Code: 404, Path: "/a.html"}, {Code: 404, Path: "/b.html"}},
	}
	for _, rules := range invalid {
		if _, err := normalizeErrorPages(rules); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeErrorPages(%+v) err = %v, want ErrInvalid", rules, err)
		}
	}

	tooMany := make([]ErrorPageRule, maxErrorPageRules+1)
	for i := range tooMany {
		tooMany[i] = ErrorPageRule{Code: 400 + i, Path: "/e.html"}
	}
	if _, err := normalizeErrorPages(tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long table err = %v, want ErrInvalid", err)
	}
}

func TestSetErrorPagesRendersDirectivesAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetErrorPages("shop", []ErrorPageRule{
		{Code: 502, Path: "/50x.html"},
		{Code: 404, Path: "/404.html"},
	})
	if err != nil {
		t.Fatalf("SetErrorPages: %v", err)
	}
	if len(site.ErrorPages) != 2 || site.ErrorPages[0].Code != 404 {
		t.Fatalf("returned rules = %+v", site.ErrorPages)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("shop"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"    error_page 404 /404.html;\n",
		"    error_page 502 /50x.html;\n",
		"    location = /404.html {\n",
		"    location = /50x.html {\n",
		`"error_pages":[{"code":404,"path":"/404.html"},{"code":502,"path":"/50x.html"}]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("config missing %q\n%s", want, text)
		}
	}
	if strings.Count(text, "try_files $uri $uri/ =404;") != 1 {
		t.Errorf("default location / changed unexpectedly:\n%s", text)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if len(list[0].ErrorPages) != 2 || list[0].ErrorPages[1].Path != "/50x.html" {
		t.Errorf("marker round-trip = %+v", list[0].ErrorPages)
	}

	if _, err := m.SetErrorPages("shop", nil); err != nil {
		t.Fatalf("clear error pages: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("shop"))
	if strings.Contains(string(body), "error_page") || strings.Contains(string(body), `"error_pages"`) {
		t.Errorf("clear left rules behind:\n%s", body)
	}
	if !strings.Contains(string(body), "try_files $uri $uri/ =404;") {
		t.Errorf("clear removed default handler:\n%s", body)
	}
}

func TestErrorPagesCoexistWithLocationOwners(t *testing.T) {
	for _, create := range []struct {
		name string
		spec Spec
	}{
		{name: "rewrite", spec: Spec{Name: "spa", Domains: []string{"spa.example.com"}, Rewrite: "spa"}},
		{name: "proxy", spec: Spec{Name: "app", Domains: []string{"app.example.com"}}},
		{name: "site-redirect", spec: Spec{Name: "moved", Domains: []string{"moved.example.com"}}},
	} {
		t.Run(create.name, func(t *testing.T) {
			m, _ := newTestManager(t)
			if _, err := m.Create(create.spec); err != nil {
				t.Fatalf("Create: %v", err)
			}
			switch create.name {
			case "proxy":
				if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
					t.Fatalf("SetProxy: %v", err)
				}
			case "site-redirect":
				if _, err := m.SetRedirect("moved", "https://new.example.com", 301, true); err != nil {
					t.Fatalf("SetRedirect: %v", err)
				}
			}
			if _, err := m.SetErrorPages(create.spec.Name, []ErrorPageRule{
				{Code: 404, Path: "/404.html"},
			}); err != nil {
				t.Fatalf("SetErrorPages with %s: %v", create.name, err)
			}
			body, _ := os.ReadFile(m.Layout.ConfigPath(create.spec.Name))
			text := string(body)
			if !strings.Contains(text, "    error_page 404 /404.html;") {
				t.Fatalf("error page directive missing:\n%s", text)
			}
			if !strings.Contains(text, "    location = /404.html {") {
				t.Fatalf("static error page location missing:\n%s", text)
			}
			switch create.name {
			case "rewrite":
				if !strings.Contains(text, "try_files $uri $uri/ /index.html;") {
					t.Fatalf("SPA handler disappeared:\n%s", text)
				}
			case "proxy":
				if !strings.Contains(text, "proxy_pass http://127.0.0.1:3000;") {
					t.Fatalf("proxy handler disappeared:\n%s", text)
				}
			case "site-redirect":
				if !strings.Contains(text, "return 301 https://new.example.com$request_uri;") {
					t.Fatalf("site redirect disappeared:\n%s", text)
				}
			}
		})
	}
}

func TestSetErrorPagesRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetErrorPages("shop", []ErrorPageRule{
		{Code: 404, Path: "/first.html"},
	}); err != nil {
		t.Fatalf("initial SetErrorPages: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	rec.cmds = nil
	rec.failOn = "-t"
	if _, err := m.SetErrorPages("shop", []ErrorPageRule{
		{Code: 404, Path: "/second.html"},
	}); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetErrorPages err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	if string(after) != string(before) {
		t.Errorf("failed rule change was not rolled back\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || len(list[0].ErrorPages) != 1 || list[0].ErrorPages[0].Path != "/first.html" {
		t.Errorf("marker after rollback = %+v", list)
	}
}

func TestMarkerRejectsBadErrorPages(t *testing.T) {
	cases := []string{
		`{"name":"shop","domains":["shop.example.com"],"root":"/tmp/shop","created_at":"2026-01-01T00:00:00Z","error_pages":[{"code":200,"path":"/ok.html"}]}`,
		`{"name":"shop","domains":["shop.example.com"],"root":"/tmp/shop","created_at":"2026-01-01T00:00:00Z","error_pages":[{"code":404,"path":"/404.html;return 500"}]}`,
		`{"name":"shop","domains":["shop.example.com"],"root":"/tmp/shop","created_at":"2026-01-01T00:00:00Z","error_pages":[{"code":404,"path":"/a.html"},{"code":404,"path":"/b.html"}]}`,
		// Same path in both tables would render a duplicate `location =`.
		`{"name":"shop","domains":["shop.example.com"],"root":"/tmp/shop","created_at":"2026-01-01T00:00:00Z","error_pages":[{"code":404,"path":"/dup.html"}],"redirect_paths":[{"path":"/dup.html","target":"https://new.example.com","code":301}]}`,
	}
	for _, payload := range cases {
		if _, ok := parseMarker(headerLine + "\n" + markerLine + payload + "\n"); ok {
			t.Errorf("parseMarker accepted invalid error page table: %s", payload)
		}
	}
}

func TestErrorPagesAndRedirectPathsRejectCollision(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetErrorPages("shop", []ErrorPageRule{{Code: 404, Path: "/dup.html"}}); err != nil {
		t.Fatalf("SetErrorPages: %v", err)
	}
	// A redirect exception on the same path must be refused with a reason…
	if _, err := m.SetRedirectPaths("shop", []RedirectRule{
		{Path: "/dup.html", Target: "https://new.example.com", Code: 301},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("colliding redirect path err = %v, want ErrInvalid", err)
	}
	// …and the reverse direction too.
	if _, err := m.SetRedirectPaths("shop", []RedirectRule{
		{Path: "/other", Target: "https://new.example.com", Code: 301},
	}); err != nil {
		t.Fatalf("SetRedirectPaths: %v", err)
	}
	if _, err := m.SetErrorPages("shop", []ErrorPageRule{{Code: 404, Path: "/other"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("colliding error page err = %v, want ErrInvalid", err)
	}
	// Neither refusal may have touched the stored tables.
	list, _ := m.List()
	if len(list) != 1 || len(list[0].ErrorPages) != 1 || list[0].ErrorPages[0].Path != "/dup.html" ||
		len(list[0].RedirectPaths) != 1 || list[0].RedirectPaths[0].Path != "/other" {
		t.Errorf("tables after refusals = %+v", list[0])
	}
}

func TestSetErrorPagesOwnershipAndName(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.SetErrorPages("../evil", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetErrorPages("ghost", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site err = %v, want ErrNotFound", err)
	}
	// A foreign vhost (no marker) must be refused, not adopted.
	foreign := m.Layout.ConfigPath("foreign")
	if err := os.WriteFile(foreign, []byte("server {\n    listen 80;\n}\n"), 0o644); err != nil {
		t.Fatalf("write foreign: %v", err)
	}
	if _, err := m.SetErrorPages("foreign", []ErrorPageRule{{Code: 404, Path: "/404.html"}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign site err = %v, want ErrNotFound", err)
	}
	body, _ := os.ReadFile(foreign)
	if strings.Contains(string(body), "error_page") {
		t.Errorf("foreign vhost was modified:\n%s", body)
	}
}
