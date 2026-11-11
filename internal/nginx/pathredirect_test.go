package nginx

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Per-path redirects are exact `location =` exceptions to the default site
// handler. These tests pin path/target/status validation, exact rendering,
// marker round-trips, coexistence with location / owners, rollback and marker
// rejection.

func TestRedirectPathsAreValidated(t *testing.T) {
	cases := []struct {
		name string
		in   []RedirectRule
		want []RedirectRule
	}{
		{
			name: "canonicalizes trailing slash and case",
			in:   []RedirectRule{{Path: "/Old/", Target: " HTTPS://New.Example.COM/x ", Code: 302}},
			want: []RedirectRule{{Path: "/Old", Target: "https://new.example.com/x", Code: 302}},
		},
	}
	for _, c := range cases {
		got, err := normalizeRedirectPaths(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(got) != len(c.want) || got[0] != c.want[0] {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}

	if got, err := normalizeRedirectPaths(nil); err != nil || got != nil {
		t.Errorf("empty table clear = %v, %v", got, err)
	}

	invalid := [][]RedirectRule{
		{{Path: "/", Target: "https://new.example.com", Code: 301}},
		{{Path: "/old/../secret", Target: "https://new.example.com", Code: 301}},
		{{Path: "/old?a=1", Target: "https://new.example.com", Code: 301}},
		{{Path: "/old;x", Target: "https://new.example.com", Code: 301}},
		{{Path: "/old", Target: "ftp://new.example.com", Code: 301}},
		{{Path: "/old", Target: "https://new.example.com;a", Code: 301}},
		{{Path: "/old", Target: "https://new.example.com", Code: 307}},
		{{Path: "/old", Target: "https://new.example.com", Code: 301},
			{Path: "/old/", Target: "https://other.example.com", Code: 302}},
		{{Path: "/.well-known/acme-challenge/token", Target: "https://new.example.com", Code: 301}},
	}
	for _, rules := range invalid {
		if _, err := normalizeRedirectPaths(rules); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeRedirectPaths(%+v) err = %v, want ErrInvalid", rules, err)
		}
	}

	tooMany := make([]RedirectRule, maxRedirectPathRules+1)
	for i := range tooMany {
		tooMany[i] = RedirectRule{Path: "/p" + string(rune('a'+i)), Target: "https://new.example.com", Code: 301}
	}
	if _, err := normalizeRedirectPaths(tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long table err = %v, want ErrInvalid", err)
	}
}

func TestSetRedirectPathsRendersExactLocationsAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetRedirectPaths("old", []RedirectRule{
		{Path: "/news", Target: "https://new.example.com/articles", Code: 301},
		{Path: "/old", Target: "https://archive.example.com", Code: 302},
	})
	if err != nil {
		t.Fatalf("SetRedirectPaths: %v", err)
	}
	if len(site.RedirectPaths) != 2 || site.RedirectPaths[1].Path != "/old" {
		t.Fatalf("returned rules = %+v", site.RedirectPaths)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("old"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		`    location = /news {
        return 301 https://new.example.com/articles$is_args$args;
    }`,
		`    location = /old {
        return 302 https://archive.example.com$is_args$args;
    }`,
		`"redirect_paths":[{"path":"/news","target":"https://new.example.com/articles","code":301},`,
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
	if len(list[0].RedirectPaths) != 2 || list[0].RedirectPaths[1].Target != "https://archive.example.com" {
		t.Errorf("marker round-trip = %+v", list[0].RedirectPaths)
	}

	if _, err := m.SetRedirectPaths("old", nil); err != nil {
		t.Fatalf("clear redirect paths: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if strings.Contains(string(body), "location = /news") || strings.Contains(string(body), `"redirect_paths"`) {
		t.Errorf("clear left rules behind:\n%s", body)
	}
	if !strings.Contains(string(body), "try_files $uri $uri/ =404;") {
		t.Errorf("clear removed default handler:\n%s", body)
	}
}

func TestRedirectPathsCoexistWithLocationOwners(t *testing.T) {
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
			if _, err := m.SetRedirectPaths(create.spec.Name, []RedirectRule{
				{Path: "/keep", Target: "https://exception.example.com", Code: 302},
			}); err != nil {
				t.Fatalf("SetRedirectPaths with %s: %v", create.name, err)
			}
			body, _ := os.ReadFile(m.Layout.ConfigPath(create.spec.Name))
			text := string(body)
			if !strings.Contains(text, "    location = /keep {") {
				t.Fatalf("exact rule missing:\n%s", text)
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

func TestSetRedirectPathsRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetRedirectPaths("old", []RedirectRule{
		{Path: "/old", Target: "https://first.example.com", Code: 301},
	}); err != nil {
		t.Fatalf("initial SetRedirectPaths: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	rec.cmds = nil
	rec.failOn = "-t"
	if _, err := m.SetRedirectPaths("old", []RedirectRule{
		{Path: "/new", Target: "https://second.example.com", Code: 302},
	}); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetRedirectPaths err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("failed rule change was not rolled back\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || len(list[0].RedirectPaths) != 1 || list[0].RedirectPaths[0].Path != "/old" {
		t.Errorf("marker after rollback = %+v", list)
	}
}

func TestMarkerRejectsBadRedirectPaths(t *testing.T) {
	cases := []string{
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_paths":[{"path":"/","target":"https://new.example.com","code":301}]}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_paths":[{"path":"/old","target":"https://new.example.com","code":307}]}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","redirect_paths":[{"path":"/old","target":"https://new.example.com;a","code":301}]}`,
	}
	for _, payload := range cases {
		if _, ok := parseMarker(headerLine + "\n" + markerLine + payload + "\n"); ok {
			t.Errorf("parseMarker accepted invalid redirect table: %s", payload)
		}
	}
}
