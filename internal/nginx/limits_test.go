package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Traffic limits are the only site feature whose configuration lives in two
// files: the vhost (server-level directives) and a zone table nginx requires
// at http level. These tests pin the input validation, the exact rendering of
// both files, the table's rebuild-on-every-change rule, the delete path,
// coexistence with the other site features, rollback across both files, and the
// two ownership doors (a foreign same-named file, and a foreign marker).

// newLimitsManager returns a manager whose host nginx.conf really contains a
// wildcard http-level include, which is what the zone table's location is
// derived from. Without that file the panel must refuse to place an http-level
// config, so every positive test has to write it.
func newLimitsManager(t *testing.T) (*Manager, *recorder) {
	t.Helper()
	m, rec := newTestManager(t)
	conf := "http {\n    include sites-enabled/*;\n    include conf.d/*.conf;\n}\n"
	if err := os.WriteFile(filepath.Join(m.Layout.ConfigDir, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	return m, rec
}

func TestTrafficLimitsAreValidated(t *testing.T) {
	cases := []struct {
		name string
		in   TrafficLimit
		want TrafficLimit
	}{
		{
			name: "lowercases and trims the rate",
			in:   TrafficLimit{RequestRate: " 200R/m ", Burst: 50},
			want: TrafficLimit{RequestRate: "200r/m", Burst: 50},
		},
		{
			name: "connections only is a valid limit",
			in:   TrafficLimit{Connections: 10},
			want: TrafficLimit{Connections: 10},
		},
		{
			name: "empty limit is the clear",
			in:   TrafficLimit{},
			want: TrafficLimit{},
		},
	}
	for _, c := range cases {
		got, err := normalizeTrafficLimit(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}

	invalid := []TrafficLimit{
		{Burst: 10},   // burst without any rate does nothing
		{Status: 429}, // a status alone is not a limit
		{RequestRate: "0r/s"},
		{RequestRate: "1M"}, // rate=1M is not the shape we render
		{RequestRate: "10r/s$"},
		{RequestRate: "10 r/s"},
		{RequestRate: "10r/h"},
		{RequestRate: "1000001r/s"},
		{RequestRate: "10r/s", Burst: maxLimitBurst + 1},
		{RequestRate: "10r/s", Connections: -1},
		{RequestRate: "10r/s", Connections: maxLimitConnections + 1},
		{RequestRate: "10r/s", Status: 404},
		{RequestRate: "10r/s", Status: 307},
	}
	for _, in := range invalid {
		if _, err := normalizeTrafficLimit(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeTrafficLimit(%+v) err = %v, want ErrInvalid", in, err)
		}
	}

	// The zone name must be injective on panel site names: two sites whose
	// names differ only by a hyphen may not share a shared-memory zone.
	if limitZoneName("a-b") == limitZoneName("ab") {
		t.Errorf("zone names collide: %s vs %s", limitZoneName("a-b"), limitZoneName("ab"))
	}
	if !limitZoneRe.MatchString(limitZoneName(strings.Repeat("a", 32))) {
		t.Errorf("longest legal site name produces an illegal zone name %q",
			limitZoneName(strings.Repeat("a", 32)))
	}
}

func TestSetLimitsWritesVhostAndZoneTable(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetLimits("blog", TrafficLimit{RequestRate: "10r/s", Burst: 20, Connections: 5, Status: 429})
	if err != nil {
		t.Fatalf("SetLimits: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v (test must precede reload)", rec.cmds, want)
	}
	if site.Limits == nil || site.Limits.RequestRate != "10r/s" || site.Limits.Burst != 20 {
		t.Fatalf("returned limits = %+v", site.Limits)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatalf("vhost not written: %v", err)
	}
	for _, want := range []string{
		"    limit_req zone=mp_blog_req burst=20 nodelay;\n",
		"    limit_conn mp_blog_conn 5;\n",
		"    limit_req_status 429;\n",
		"    limit_conn_status 429;\n",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("vhost missing %q\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "limit_req zone=mp_blog_req;\n") {
		t.Errorf("vhost rendered the no-burst form next to the burst form:\n%s", body)
	}

	tablePath := mustLimitsPath(t, m)
	table, err := os.ReadFile(tablePath)
	if err != nil {
		t.Fatalf("zone table not written at %s: %v", tablePath, err)
	}
	for _, want := range []string{
		`limit_req_zone $binary_remote_addr zone=mp_blog_req:10m rate=10r/s;`,
		`limit_conn_zone $binary_remote_addr zone=mp_blog_conn:10m;`,
		limitsMarkerLine,
	} {
		if !strings.Contains(string(table), want) {
			t.Errorf("zone table missing %q\n%s", want, table)
		}
	}
	// The Debian layout may include both `sites-enabled/*` and
	// `sites-enabled/*.conf`, so the table has to sit in the directory whose
	// glob is the unqualified one: that is where it is read exactly once.
	if filepath.Dir(tablePath) != m.Layout.Enabled {
		t.Errorf("zone table landed in %s, want the directory included as * (%s)",
			filepath.Dir(tablePath), m.Layout.Enabled)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}
	got := list[0].Limits
	if got == nil || *got != (TrafficLimit{RequestRate: "10r/s", Burst: 20, Connections: 5, Status: 429}) {
		t.Errorf("marker round-trip = %+v", got)
	}
}

func TestLimitsTableRebuildsFromSiteList(t *testing.T) {
	m, _ := newLimitsManager(t)
	for _, name := range []string{"api-shop", "blog"} {
		if _, err := m.Create(Spec{Name: name, Domains: []string{name + ".example.com"}}); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	if _, err := m.SetLimits("blog", TrafficLimit{RequestRate: "200r/m"}); err != nil {
		t.Fatalf("SetLimits blog: %v", err)
	}
	if _, err := m.SetLimits("api-shop", TrafficLimit{Connections: 30}); err != nil {
		t.Fatalf("SetLimits api-shop: %v", err)
	}
	table, err := os.ReadFile(mustLimitsPath(t, m))
	if err != nil {
		t.Fatalf("zone table: %v", err)
	}
	if !strings.Contains(string(table), "zone=mp_api_shop_conn:10m;") ||
		!strings.Contains(string(table), "zone=mp_blog_req:10m rate=200r/m;") {
		t.Fatalf("table does not carry both zones:\n%s", table)
	}
	if strings.Contains(string(table), "zone=mp_api_shop_req") {
		t.Errorf("table defines a request zone for a connections-only site:\n%s", table)
	}

	// Clearing one site must rewrite the whole table, not merely append.
	if _, err := m.SetLimits("blog", TrafficLimit{}); err != nil {
		t.Fatalf("clear blog: %v", err)
	}
	table, _ = os.ReadFile(mustLimitsPath(t, m))
	if strings.Contains(string(table), "mp_blog") {
		t.Errorf("cleared site still has a zone:\n%s", table)
	}
	if !strings.Contains(string(table), "mp_api_shop_conn") {
		t.Errorf("the other site's zone disappeared:\n%s", table)
	}
	blogBody, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if strings.Contains(string(blogBody), "limit_req ") {
		t.Errorf("cleared vhost still applies a limit:\n%s", blogBody)
	}
}

func TestDeleteRemovesZoneAndDropsEmptyTable(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetLimits("blog", TrafficLimit{RequestRate: "10r/s"}); err != nil {
		t.Fatalf("SetLimits: %v", err)
	}
	tablePath := mustLimitsPath(t, m)
	if _, err := os.Stat(tablePath); err != nil {
		t.Fatalf("zone table should exist before delete: %v", err)
	}
	if _, err := m.Delete("blog"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// An empty table file reached through `include conf.d/*.conf` does not
	// parse at http level, so the last zone has to remove the file entirely.
	if _, err := os.Stat(tablePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("zone table left behind after the last limited site was deleted (err = %v)", err)
	}
}

func TestLimitsCoexistWithLocationOwners(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetPHP("shop", "8.3", "/run/php/php8.3-fpm.sock"); err != nil {
		t.Fatalf("SetPHP: %v", err)
	}
	if _, err := m.SetProxy("shop", "http://127.0.0.1:3000", true); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if _, err := m.SetRealIP("shop", []string{"10.0.0.0/8"}, "X-Forwarded-For"); err != nil {
		t.Fatalf("SetRealIP: %v", err)
	}
	if _, err := m.SetAuth("shop", "admin", "hunter2hunter2"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if _, err := m.SetRedirectPaths("shop", []RedirectRule{
		{Path: "/news", Target: "https://new.example.com/articles", Code: 301},
	}); err != nil {
		t.Fatalf("SetRedirectPaths: %v", err)
	}
	if _, err := m.SetLimits("shop", TrafficLimit{RequestRate: "50r/s", Burst: 100}); err != nil {
		t.Fatalf("SetLimits: %v", err)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("shop"))
	if err != nil {
		t.Fatalf("vhost: %v", err)
	}
	for _, want := range []string{
		"    limit_req zone=mp_shop_req burst=100 nodelay;\n",
		"    location = /news {",
		"fastcgi_pass unix:/run/php/php8.3-fpm.sock;",
		"real_ip_header X-Forwarded-For;",
		"auth_basic ",
		"proxy_pass http://127.0.0.1:3000;",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("vhost lost %q when limits were added:\n%s", want, body)
		}
	}
	// Limits must not take over the catch-all handler.
	if strings.Contains(string(body), "location / {\n        limit_req") {
		t.Errorf("limits rendered inside location / instead of at server level:\n%s", body)
	}

	list, _ := m.List()
	if len(list) != 1 || list[0].ProxyTarget == "" || list[0].Limits == nil {
		t.Errorf("marker after combined writes = %+v", list)
	}

	// Clearing the limit must leave every other feature alone.
	if _, err := m.SetLimits("shop", TrafficLimit{}); err != nil {
		t.Fatalf("clear limits: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("shop"))
	if strings.Contains(string(body), "limit_req") || strings.Contains(string(body), "limit_conn") {
		t.Errorf("cleared site still renders limit directives:\n%s", body)
	}
	for _, want := range []string{"proxy_pass http://127.0.0.1:3000;", "location = /news {"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("clearing limits removed %q:\n%s", want, body)
		}
	}
	if _, err := os.Stat(mustLimitsPath(t, m)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("zone table should be gone after the only limited site was cleared (err = %v)", err)
	}
}

func TestSetLimitsRollsBackBothFiles(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetLimits("blog", TrafficLimit{RequestRate: "10r/s"}); err != nil {
		t.Fatalf("SetLimits: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	beforeTable, _ := os.ReadFile(mustLimitsPath(t, m))

	for _, fail := range []string{"-t", "reload"} {
		rec.cmds = nil
		rec.failOn = fail
		_, err := m.SetLimits("blog", TrafficLimit{RequestRate: "5r/s", Burst: 1})
		if !errors.Is(err, ErrConfigRejected) {
			t.Fatalf("failed SetLimits (failOn %q) err = %v, want ErrConfigRejected", fail, err)
		}
		after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
		if string(after) != string(before) {
			t.Errorf("vhost not rolled back after %q failure\nbefore:\n%s\nafter:\n%s", fail, before, after)
		}
		afterTable, _ := os.ReadFile(mustLimitsPath(t, m))
		if string(afterTable) != string(beforeTable) {
			t.Errorf("zone table not rolled back after %q failure\nbefore:\n%s\nafter:\n%s",
				fail, beforeTable, afterTable)
		}
		list, _ := m.List()
		if len(list) != 1 || list[0].Limits == nil || list[0].Limits.RequestRate != "10r/s" {
			t.Errorf("marker after rollback (%q) = %+v", fail, list)
		}
		rec.failOn = ""
	}
}

func TestSetLimitsRefusesForeignZoneTable(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tablePath := mustLimitsPath(t, m)
	if err := os.MkdirAll(filepath.Dir(tablePath), 0o755); err != nil {
		t.Fatal(err)
	}
	const foreign = "limit_req_zone $binary_remote_addr zone=someone_else:10m rate=999r/s;\n"
	if err := os.WriteFile(tablePath, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	rec.cmds = nil
	if _, err := m.SetLimits("blog", TrafficLimit{RequestRate: "10r/s"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SetLimits over a foreign zone table err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("vhost changed even though the table was refused:\n%s", after)
	}
	if b, _ := os.ReadFile(tablePath); string(b) != foreign {
		t.Errorf("foreign zone table was overwritten:\n%s", b)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx was invoked for a refused two-file write: %v", rec.cmds)
	}
}

func TestMarkerRejectsBadLimits(t *testing.T) {
	cases := []string{
		`{"name":"blog","domains":["blog.example.com"],"root":"/tmp/blog","created_at":"2026-01-01T00:00:00Z","limits":{"request_rate":"10r/s","burst":-5}}`,
		`{"name":"blog","domains":["blog.example.com"],"root":"/tmp/blog","created_at":"2026-01-01T00:00:00Z","limits":{"request_rate":"1M"}}`,
		`{"name":"blog","domains":["blog.example.com"],"root":"/tmp/blog","created_at":"2026-01-01T00:00:00Z","limits":{"burst":10}}`,
		`{"name":"blog","domains":["blog.example.com"],"root":"/tmp/blog","created_at":"2026-01-01T00:00:00Z","limits":{"request_rate":"10r/s","status":200}}`,
	}
	for _, payload := range cases {
		if _, ok := parseMarker(headerLine + "\n" + markerLine + payload + "\n"); ok {
			t.Errorf("parseMarker accepted an invalid limits marker: %s", payload)
		}
	}
	// A cleared marker must round-trip to "no limits", not to an empty struct.
	p, ok := parseMarker(headerLine + "\n" +
		markerLine + `{"name":"blog","domains":["blog.example.com"],"root":"/tmp/blog","created_at":"2026-01-01T00:00:00Z","limits":{}}` + "\n")
	if !ok {
		t.Fatalf("parseMarker rejected an empty limits marker")
	}
	if p.Limits != nil {
		t.Errorf("empty limits marker = %+v, want nil", p.Limits)
	}
}

func TestConfDLayoutKeepsZoneTableInConfD(t *testing.T) {
	base := t.TempDir()
	confd := filepath.Join(base, "conf.d")
	if err := os.MkdirAll(confd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "nginx.conf"),
		[]byte("http {\n    include conf.d/*.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := New(base, filepath.Join(base, "www"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Layout.Mode != ModeConfD {
		t.Fatalf("layout mode = %v, want conf.d", m.Layout.Mode)
	}
	m.Run = (&recorder{}).run
	if got := mustLimitsPath(t, m); got != filepath.Join(confd, limitsFileName) {
		t.Errorf("limitsPath = %s, want %s", got, filepath.Join(confd, limitsFileName))
	}
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetLimits("blog", TrafficLimit{RequestRate: "10r/s"}); err != nil {
		t.Fatalf("SetLimits: %v", err)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatalf("vhost: %v", err)
	}
	if !strings.Contains(string(body), "limit_req zone=mp_blog_req;") {
		t.Errorf("conf.d vhost missing the limit directive:\n%s", body)
	}
	if _, err := os.Stat(mustLimitsPath(t, m)); err != nil {
		t.Errorf("conf.d zone table not written: %v", err)
	}
}

func TestLimitsRefuseWithoutHttpLevelInclude(t *testing.T) {
	m, rec := newTestManager(t) // no nginx.conf at all
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	if _, err := m.SetLimits("blog", TrafficLimit{RequestRate: "10r/s"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SetLimits with no resolvable http include err = %v, want ErrInvalid", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx was invoked for a refused write: %v", rec.cmds)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if strings.Contains(string(body), "limit_") {
		t.Errorf("vhost carries limit directives although the table was refused:\n%s", body)
	}
	// A host with no traffic limit at all must keep working exactly as before:
	// the include probe may not become a new precondition for site management.
	if _, err := m.SetRedirectPaths("blog", []RedirectRule{
		{Path: "/old", Target: "https://new.example.com", Code: 301},
	}); err != nil {
		t.Errorf("other site writes now require the http include: %v", err)
	}
	if _, err := m.Delete("blog"); err != nil {
		t.Errorf("deleting a never-limited site now requires the http include: %v", err)
	}
}

func TestLimitsPathIgnoresNonWildcardIncludes(t *testing.T) {
	m, _ := newLimitsManager(t)
	if err := os.WriteFile(filepath.Join(m.Layout.ConfigDir, "nginx.conf"),
		[]byte("http {\n    include mime.types;\n    include conf.d/app.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.limitsPath(); !errors.Is(err, ErrInvalid) {
		t.Errorf("limitsPath accepted a config with no wildcard include: %v", err)
	}
}

func TestLimitsPathFollowsTheHostsOwnGlob(t *testing.T) {
	m, _ := newLimitsManager(t)
	// A Debian-ish host that only includes sites-enabled/*.conf: the table
	// still has to be found, in that directory, because the panel's own name
	// ends in .conf.
	if err := os.WriteFile(filepath.Join(m.Layout.ConfigDir, "nginx.conf"),
		[]byte("http {\n    include sites-enabled/*.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := m.limitsPath()
	if err != nil {
		t.Fatalf("limitsPath: %v", err)
	}
	if want := filepath.Join(m.Layout.Enabled, limitsFileName); got != want {
		t.Errorf("limitsPath = %s, want %s", got, want)
	}
	// And an unrelated included directory is still a legal home for the table.
	if err := os.WriteFile(filepath.Join(m.Layout.ConfigDir, "nginx.conf"),
		[]byte("http {\n    include conf.d/*.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = m.limitsPath()
	if err != nil {
		t.Fatalf("limitsPath (conf.d only): %v", err)
	}
	if want := filepath.Join(m.Layout.ConfigDir, "conf.d", limitsFileName); got != want {
		t.Errorf("limitsPath = %s, want %s", got, want)
	}
}

// mustLimitsPath fails the test rather than the caller when the host's config
// cannot be resolved; the error paths are covered on purpose elsewhere.
func mustLimitsPath(t *testing.T, m *Manager) string {
	t.Helper()
	p, err := m.limitsPath()
	if err != nil {
		t.Fatalf("limitsPath: %v", err)
	}
	return p
}
