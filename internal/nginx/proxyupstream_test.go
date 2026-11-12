package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Multi-upstream balancing writes two files per change: the vhost's fixed
// proxy_pass and the panel-owned http-level upstream table. These tests pin
// validation, exact rendering, table rebuilds from the site list, the
// single/multi proxy handover, rollback, foreign-file refusal and marker
// rejection.

func TestProxyUpstreamsAreValidated(t *testing.T) {
	got, err := normalizeProxyUpstreams([]ProxyUpstream{
		{Target: " HTTP://App1.Example.COM:3000 ", Weight: 0},
		{Target: "http://127.0.0.1:3001", Weight: 5},
	})
	if err != nil {
		t.Fatalf("normalizeProxyUpstreams: %v", err)
	}
	want := []ProxyUpstream{
		{Target: "http://app1.example.com:3000", Weight: 1},
		{Target: "http://127.0.0.1:3001", Weight: 5},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("normalized = %+v, want %+v", got, want)
	}
	if got, err := normalizeProxyUpstreams(nil); err != nil || got != nil {
		t.Errorf("empty table clear = %v, %v", got, err)
	}

	invalid := [][]ProxyUpstream{
		{{Target: "https://app.example.com:3000"}},
		{{Target: "http://app.example.com:3000/api"}},
		{{Target: "http://app.example.com:0"}},
		{{Target: "http://app.example.com:3000", Weight: -1}},
		{{Target: "http://app.example.com:3000", Weight: maxUpstreamWeight + 1}},
		{{Target: "http://app.example.com:3000"}, {Target: "http://APP.example.com:3000"}},
		{{Target: "http://app.example.com:3000;x"}},
		{{Target: "ftp://app.example.com:3000"}},
	}
	for _, ups := range invalid {
		if _, err := normalizeProxyUpstreams(ups); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeProxyUpstreams(%+v) err = %v, want ErrInvalid", ups, err)
		}
	}
	tooMany := make([]ProxyUpstream, maxProxyUpstreams+1)
	for i := range tooMany {
		tooMany[i] = ProxyUpstream{Target: "http://127.0.0.1:" + strconv.Itoa(3000+i)}
	}
	if _, err := normalizeProxyUpstreams(tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long table err = %v, want ErrInvalid", err)
	}

	for _, m := range []string{"", "round_robin", "ip_hash", "least_conn"} {
		if _, err := normalizeProxyLBMethod(m); err != nil {
			t.Errorf("method %q: %v", m, err)
		}
	}
	if m, _ := normalizeProxyLBMethod("round_robin"); m != "" {
		t.Errorf("round_robin normalized to %q, want empty (nginx default)", m)
	}
	for _, m := range []string{"random", "hash", "fair", "url_hash"} {
		if _, err := normalizeProxyLBMethod(m); !errors.Is(err, ErrInvalid) {
			t.Errorf("method %q err = %v, want ErrInvalid", m, err)
		}
	}
}

func TestSetProxyUpstreamsWritesVhostAndTable(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetProxyUpstreams("app", []ProxyUpstream{
		{Target: "http://127.0.0.1:3000", Weight: 3},
		{Target: "http://127.0.0.1:3001"},
	}, "least_conn", true)
	if err != nil {
		t.Fatalf("SetProxyUpstreams: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}
	if len(site.ProxyUpstreams) != 2 || site.ProxyLBMethod != "least_conn" || !site.ProxyWebSocket {
		t.Fatalf("returned site = %+v", site)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("app"))
	if err != nil {
		t.Fatalf("vhost not written: %v", err)
	}
	for _, want := range []string{
		"        proxy_pass http://mp_app_upstream;\n",
		"        proxy_set_header Upgrade $http_upgrade;\n",
		`"proxy_upstreams":[{"target":"http://127.0.0.1:3000","weight":3},{"target":"http://127.0.0.1:3001","weight":1}]`,
		`"proxy_lb_method":"least_conn"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("vhost missing %q\n%s", want, body)
		}
	}

	tablePath, err := m.upstreamsPath()
	if err != nil {
		t.Fatalf("upstreamsPath: %v", err)
	}
	table, err := os.ReadFile(tablePath)
	if err != nil {
		t.Fatalf("upstream table not written at %s: %v", tablePath, err)
	}
	for _, want := range []string{
		"upstream mp_app_upstream {\n",
		"    least_conn;\n",
		"    server 127.0.0.1:3000 weight=3;\n",
		"    server 127.0.0.1:3001;\n",
		upstreamsMarkerLine,
	} {
		if !strings.Contains(string(table), want) {
			t.Errorf("table missing %q\n%s", want, table)
		}
	}
	if filepath.Dir(tablePath) != m.Layout.Enabled {
		t.Errorf("table landed in %s, want the directory included as * (%s)", filepath.Dir(tablePath), m.Layout.Enabled)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}
	if len(list[0].ProxyUpstreams) != 2 || list[0].ProxyLBMethod != "least_conn" || !list[0].ProxyWebSocket {
		t.Errorf("marker round-trip = %+v", list[0])
	}

	// ip_hash renders its directive; the default method renders none.
	if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{
		{Target: "http://127.0.0.1:3000"},
		{Target: "http://127.0.0.1:3001"},
	}, "ip_hash", false); err != nil {
		t.Fatalf("ip_hash: %v", err)
	}
	table, _ = os.ReadFile(tablePath)
	if !strings.Contains(string(table), "    ip_hash;\n") {
		t.Errorf("ip_hash directive missing:\n%s", table)
	}
	if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{
		{Target: "http://127.0.0.1:3000"},
		{Target: "http://127.0.0.1:3001"},
	}, "round_robin", false); err != nil {
		t.Fatalf("round_robin: %v", err)
	}
	table, _ = os.ReadFile(tablePath)
	if strings.Contains(string(table), "ip_hash") || strings.Contains(string(table), "round_robin") {
		t.Errorf("default method must render no directive:\n%s", table)
	}
}

func TestUpstreamsTableRebuildsFromSiteList(t *testing.T) {
	m, _ := newLimitsManager(t)
	for _, name := range []string{"api-shop", "blog"} {
		if _, err := m.Create(Spec{Name: name, Domains: []string{name + ".example.com"}}); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	ups := []ProxyUpstream{{Target: "http://127.0.0.1:3000"}, {Target: "http://127.0.0.1:3001"}}
	if _, err := m.SetProxyUpstreams("blog", ups, "", false); err != nil {
		t.Fatalf("SetProxyUpstreams blog: %v", err)
	}
	if _, err := m.SetProxyUpstreams("api-shop", ups, "ip_hash", false); err != nil {
		t.Fatalf("SetProxyUpstreams api-shop: %v", err)
	}
	tablePath, _ := m.upstreamsPath()
	table, _ := os.ReadFile(tablePath)
	for _, want := range []string{"upstream mp_blog_upstream {", "upstream mp_api_shop_upstream {"} {
		if !strings.Contains(string(table), want) {
			t.Errorf("table missing %q:\n%s", want, table)
		}
	}
	// Clearing one site keeps the other's block.
	if _, err := m.SetProxyUpstreams("blog", nil, "", false); err != nil {
		t.Fatalf("clear blog: %v", err)
	}
	table, _ = os.ReadFile(tablePath)
	if strings.Contains(string(table), "mp_blog_upstream") || !strings.Contains(string(table), "mp_api_shop_upstream") {
		t.Errorf("table after clearing one site:\n%s", table)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if strings.Contains(string(body), "proxy_pass") {
		t.Errorf("cleared site still proxies:\n%s", body)
	}
	// Clearing the last one deletes the file: an empty http-level include
	// does not parse.
	if _, err := m.SetProxyUpstreams("api-shop", nil, "", false); err != nil {
		t.Fatalf("clear api-shop: %v", err)
	}
	if _, err := os.Stat(tablePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("table still exists after the last upstream went away: %v", err)
	}
}

func TestDeleteRemovesUpstreamBlockAndDropsEmptyTable(t *testing.T) {
	m, _ := newLimitsManager(t)
	for _, name := range []string{"app", "web"} {
		if _, err := m.Create(Spec{Name: name, Domains: []string{name + ".example.com"}}); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	ups := []ProxyUpstream{{Target: "http://127.0.0.1:3000"}, {Target: "http://127.0.0.1:3001"}}
	if _, err := m.SetProxyUpstreams("app", ups, "", false); err != nil {
		t.Fatalf("SetProxyUpstreams app: %v", err)
	}
	if _, err := m.SetProxyUpstreams("web", ups, "", false); err != nil {
		t.Fatalf("SetProxyUpstreams web: %v", err)
	}
	if _, err := m.Delete("app"); err != nil {
		t.Fatalf("Delete app: %v", err)
	}
	tablePath, _ := m.upstreamsPath()
	table, _ := os.ReadFile(tablePath)
	if strings.Contains(string(table), "mp_app_upstream") || !strings.Contains(string(table), "mp_web_upstream") {
		t.Errorf("table after delete:\n%s", table)
	}
	if _, err := m.Delete("web"); err != nil {
		t.Fatalf("Delete web: %v", err)
	}
	if _, err := os.Stat(tablePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("table still exists after the last site was deleted: %v", err)
	}
}

func TestProxyFormsHandOverAndExcludeLocationOwners(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ups := []ProxyUpstream{{Target: "http://127.0.0.1:3000"}, {Target: "http://127.0.0.1:3001"}}
	// Single target first, then the balancing table replaces it.
	if _, err := m.SetProxy("app", "http://127.0.0.1:9000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	site, err := m.SetProxyUpstreams("app", ups, "", false)
	if err != nil {
		t.Fatalf("SetProxyUpstreams over single target: %v", err)
	}
	if site.ProxyTarget != "" {
		t.Errorf("single target survived the handover: %+v", site)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if strings.Contains(string(body), "proxy_pass http://127.0.0.1:9000") {
		t.Errorf("old single target still rendered:\n%s", body)
	}
	// Back to a single target: the upstream table must disappear with it.
	if _, err := m.SetProxy("app", "http://127.0.0.1:9000", false); err != nil {
		t.Fatalf("SetProxy back: %v", err)
	}
	tablePath, _ := m.upstreamsPath()
	if _, err := os.Stat(tablePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("table survived the handover back to a single target: %v", err)
	}
	list, _ := m.List()
	if len(list[0].ProxyUpstreams) != 0 || list[0].ProxyLBMethod != "" {
		t.Errorf("marker kept upstreams after handover: %+v", list[0])
	}

	// While the balancing table owns location /, the other owners are refused.
	if _, err := m.SetProxyUpstreams("app", ups, "", false); err != nil {
		t.Fatalf("re-enable upstreams: %v", err)
	}
	if _, err := m.SetRewrite("app", "spa"); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetRewrite over upstreams err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetRedirect("app", "https://new.example.com", 301, true); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetRedirect over upstreams err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetHotlink("app", true, true); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetHotlink over upstreams err = %v, want ErrInvalid", err)
	}
	// And the reverse: a rewrite site refuses the balancing table.
	if _, err := m.SetProxyUpstreams("app", nil, "", false); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := m.SetRewrite("app", "spa"); err != nil {
		t.Fatalf("SetRewrite: %v", err)
	}
	if _, err := m.SetProxyUpstreams("app", ups, "", false); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetProxyUpstreams over rewrite err = %v, want ErrInvalid", err)
	}
}

func TestSetProxyUpstreamsRollsBackBothFiles(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ups := []ProxyUpstream{{Target: "http://127.0.0.1:3000"}, {Target: "http://127.0.0.1:3001"}}
	if _, err := m.SetProxyUpstreams("app", ups, "", false); err != nil {
		t.Fatalf("initial: %v", err)
	}
	tablePath, _ := m.upstreamsPath()
	beforeVhost, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	beforeTable, _ := os.ReadFile(tablePath)
	rec.failOn = "-t"
	if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{
		{Target: "http://127.0.0.1:4000"},
	}, "ip_hash", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed write err = %v, want ErrConfigRejected", err)
	}
	afterVhost, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	afterTable, _ := os.ReadFile(tablePath)
	if string(afterVhost) != string(beforeVhost) || string(afterTable) != string(beforeTable) {
		t.Errorf("failed two-file write was not rolled back")
	}
	// A failed clear must also restore the table it tried to delete.
	if _, err := m.SetProxyUpstreams("app", nil, "", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed clear err = %v, want ErrConfigRejected", err)
	}
	if b, err := os.ReadFile(tablePath); err != nil || string(b) != string(beforeTable) {
		t.Errorf("failed clear did not restore the table: %v", err)
	}
}

func TestSetProxyUpstreamsRefusesForeignTable(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tablePath, _ := m.upstreamsPath()
	if err := os.MkdirAll(filepath.Dir(tablePath), 0o755); err != nil {
		t.Fatal(err)
	}
	const foreign = "upstream someone_else {\n    server 10.0.0.1:80;\n}\n"
	if err := os.WriteFile(tablePath, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	rec.cmds = nil
	if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{
		{Target: "http://127.0.0.1:3000"},
	}, "", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("write over a foreign table err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if string(after) != string(before) {
		t.Errorf("vhost changed even though the table was refused:\n%s", after)
	}
	if b, _ := os.ReadFile(tablePath); string(b) != foreign {
		t.Errorf("foreign table was overwritten:\n%s", b)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx was invoked for a refused two-file write: %v", rec.cmds)
	}
}

func TestMarkerRejectsBadUpstreams(t *testing.T) {
	base := `{"name":"app","domains":["app.example.com"],"root":"/tmp/app","created_at":"2026-01-01T00:00:00Z"`
	cases := []string{
		base + `,"proxy_upstreams":[{"target":"https://127.0.0.1:3000"}]}`,
		base + `,"proxy_upstreams":[{"target":"http://127.0.0.1:3000/api"}]}`,
		base + `,"proxy_upstreams":[{"target":"http://127.0.0.1:3000","weight":101}]}`,
		base + `,"proxy_upstreams":[{"target":"http://127.0.0.1:3000"}],"proxy_lb_method":"random"}`,
		base + `,"proxy_target":"http://127.0.0.1:9000","proxy_upstreams":[{"target":"http://127.0.0.1:3000"}]}`,
		base + `,"hotlink":true,"proxy_upstreams":[{"target":"http://127.0.0.1:3000"}]}`,
		base + `,"proxy_upstreams":[{"target":"http://127.0.0.1:3000"},{"target":"http://127.0.0.1:3000"}]}`,
	}
	for _, payload := range cases {
		if _, ok := parseMarker(headerLine + "\n" + markerLine + payload + "\n"); ok {
			t.Errorf("parseMarker accepted invalid upstream marker: %s", payload)
		}
	}
}

func TestUpstreamsRefuseWithoutHttpLevelInclude(t *testing.T) {
	m, rec := newTestManager(t) // no nginx.conf at all
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{
		{Target: "http://127.0.0.1:3000"},
	}, "", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SetProxyUpstreams with no resolvable http include err = %v, want ErrInvalid", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx was invoked for a refused write: %v", rec.cmds)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if strings.Contains(string(body), "proxy_pass") {
		t.Errorf("vhost carries proxy_pass although the table was refused:\n%s", body)
	}
	// A host with no balancing at all keeps working exactly as before.
	if _, err := m.SetProxy("app", "http://127.0.0.1:9000", false); err != nil {
		t.Errorf("single-target proxy now requires the http include: %v", err)
	}
	if _, err := m.Delete("app"); err != nil {
		t.Errorf("deleting a never-balanced site now requires the http include: %v", err)
	}
}

func TestProxyUpstreamsClearValidationAndOwnership(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.SetProxyUpstreams("../evil", nil, "", false); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetProxyUpstreams("ghost", nil, "", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site err = %v, want ErrNotFound", err)
	}
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetProxyUpstreams("app", nil, "", true); !errors.Is(err, ErrInvalid) {
		t.Errorf("websocket without upstreams err = %v, want ErrInvalid", err)
	}
	// Clearing a site that never had upstreams is a no-op success.
	if _, err := m.SetProxyUpstreams("app", nil, "", false); err != nil {
		t.Errorf("no-op clear: %v", err)
	}
}
