package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Proxy response caching is the third two-file site feature: the vhost gets
// fixed location-level directives and the http context gets a panel-owned
// proxy_cache_path table. These tests pin validation, exact rendering of both
// files, the rebuild-from-list rule, the handover with both proxy forms, the
// delete path, rollback across both files, the ownership door, and the
// no-include refusal.

func TestProxyCacheValidated(t *testing.T) {
	ok := &ProxyCache{ValidSeconds: 60, MaxSizeMB: 1024, InactiveMinutes: 60}
	got, err := normalizeProxyCache(ok)
	if err != nil || got == nil || *got != *ok {
		t.Fatalf("normalizeProxyCache(valid) = %+v, %v", got, err)
	}
	if got == ok {
		t.Errorf("normalizeProxyCache must copy, not alias the request struct")
	}
	if c, err := normalizeProxyCache(nil); c != nil || err != nil {
		t.Errorf("nil policy = %+v, %v; want nil, nil (the clear)", c, err)
	}
	invalid := []*ProxyCache{
		{ValidSeconds: 0, MaxSizeMB: 1024, InactiveMinutes: 60},
		{ValidSeconds: maxCacheValidSeconds + 1, MaxSizeMB: 1024, InactiveMinutes: 60},
		{ValidSeconds: 60, MaxSizeMB: minCacheMaxSizeMB - 1, InactiveMinutes: 60},
		{ValidSeconds: 60, MaxSizeMB: maxCacheMaxSizeMB + 1, InactiveMinutes: 60},
		{ValidSeconds: 60, MaxSizeMB: 1024, InactiveMinutes: 0},
		{ValidSeconds: 60, MaxSizeMB: 1024, InactiveMinutes: maxCacheInactiveMinute + 1},
	}
	for _, in := range invalid {
		if _, err := normalizeProxyCache(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeProxyCache(%+v) err = %v, want ErrInvalid", in, err)
		}
	}
	if cacheZoneName("a-b") == cacheZoneName("ab") {
		t.Errorf("cache zone names collide")
	}
}

func TestSetProxyCacheWritesVhostAndTable(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 512, InactiveMinutes: 30})
	if err != nil {
		t.Fatalf("SetProxyCache: %v", err)
	}
	if site.ProxyCache == nil || site.ProxyCache.ValidSeconds != 60 {
		t.Fatalf("returned cache = %+v", site.ProxyCache)
	}
	if want := "nginx -t|nginx -s reload"; strings.Join(rec.cmds, "|") != want {
		t.Errorf("commands = %v, want %s", rec.cmds, want)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("app"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"        proxy_cache mp_app_cache;\n",
		"        proxy_cache_key \"$scheme|$host|$request_method|$request_uri\";\n",
		"        proxy_cache_methods GET HEAD;\n",
		"        proxy_cache_valid 200 302 60s;\n",
		"        proxy_cache_lock on;\n",
		"        proxy_cache_bypass $http_authorization $http_cookie;\n",
		"        proxy_no_cache $http_authorization $http_cookie;\n",
		"        add_header X-Cache-Status $upstream_cache_status always;\n",
		`"proxy_cache":{"valid_seconds":60,"max_size_mb":512,"inactive_minutes":30}`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("vhost missing %q\n%s", want, body)
		}
	}
	// The cache directives must be inside the proxy location, after proxy_pass.
	idxPass := strings.Index(string(body), "proxy_pass http://127.0.0.1:3000;")
	idxCache := strings.Index(string(body), "proxy_cache mp_app_cache;")
	if idxPass < 0 || idxCache < idxPass {
		t.Errorf("cache directives not rendered inside the proxy location:\n%s", body)
	}
	tablePath, err := m.cacheTablePath()
	if err != nil {
		t.Fatal(err)
	}
	table, err := os.ReadFile(tablePath)
	if err != nil {
		t.Fatalf("cache table not written: %v", err)
	}
	wantLine := "proxy_cache_path " + m.cacheDirFor("app") +
		" levels=1:2 keys_zone=mp_app_cache:10m max_size=512m inactive=30m use_temp_path=off;"
	if !strings.Contains(string(table), wantLine) || !strings.Contains(string(table), cacheMarkerLine) {
		t.Errorf("cache table missing definition or marker:\n%s", table)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].ProxyCache == nil || list[0].ProxyCache.MaxSizeMB != 512 {
		t.Errorf("marker round-trip = %+v, %v", list, err)
	}
}

func TestProxyCacheRequiresProxyOwner(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	_, err := m.SetProxyCache("blog", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("cache on static site err = %v, want ErrInvalid", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx invoked for refused cache: %v", rec.cmds)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if strings.Contains(string(body), "proxy_cache") {
		t.Errorf("refused cache changed the vhost:\n%s", body)
	}
	// Clearing on a static site is a no-op success, not an error.
	if _, err := m.SetProxyCache("blog", nil); err != nil {
		t.Errorf("clear on uncached site: %v", err)
	}
}

func TestProxyCacheWorksWithUpstreamTable(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetProxyUpstreams("shop", []ProxyUpstream{{Target: "http://127.0.0.1:3000"}}, "", false); err != nil {
		t.Fatalf("SetProxyUpstreams: %v", err)
	}
	if _, err := m.SetProxyCache("shop", &ProxyCache{ValidSeconds: 10, MaxSizeMB: 100, InactiveMinutes: 5}); err != nil {
		t.Fatalf("SetProxyCache on balanced site: %v", err)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	if !strings.Contains(string(body), "proxy_pass http://mp_shop_upstream;") ||
		!strings.Contains(string(body), "proxy_cache mp_shop_cache;") {
		t.Errorf("balanced proxy lost pass or cache:\n%s", body)
	}
	// Handover multi→single keeps the cache: the policy belongs to the site's
	// proxy, not to one backend shape.
	s, err := m.SetProxy("shop", "http://127.0.0.1:4000", false)
	if err != nil || s.ProxyCache == nil {
		t.Fatalf("handover to single dropped cache: %+v, %v", s.ProxyCache, err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("shop"))
	if !strings.Contains(string(body), "proxy_cache mp_shop_cache;") {
		t.Errorf("handover lost cache directives:\n%s", body)
	}
	table, err := os.ReadFile(mustCacheTablePath(t, m))
	if err != nil || !strings.Contains(string(table), "mp_shop_cache") {
		t.Errorf("cache table lost the row on handover: %v\n%s", err, table)
	}
	// And back single→multi.
	s, err = m.SetProxyUpstreams("shop", []ProxyUpstream{{Target: "http://127.0.0.1:3000"}}, "ip_hash", false)
	if err != nil || s.ProxyCache == nil {
		t.Fatalf("handover to multi dropped cache: %+v, %v", s.ProxyCache, err)
	}
}

func TestClearingProxyDropsCacheAndBytes(t *testing.T) {
	for _, form := range []string{"single", "multi"} {
		t.Run(form, func(t *testing.T) {
			m, _ := newLimitsManager(t)
			if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if form == "single" {
				if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{{Target: "http://127.0.0.1:3000"}}, "", false); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10}); err != nil {
				t.Fatal(err)
			}
			// Simulate cached bytes on disk.
			if err := os.MkdirAll(m.cacheDirFor("app"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.cacheDirFor("app"), "entry"), []byte("cached"), 0o644); err != nil {
				t.Fatal(err)
			}
			var s Site
			var err error
			if form == "single" {
				s, err = m.SetProxy("app", "", false)
			} else {
				s, err = m.SetProxyUpstreams("app", nil, "", false)
			}
			if err != nil || s.ProxyCache != nil {
				t.Fatalf("clear proxy kept cache: %+v, %v", s.ProxyCache, err)
			}
			body, _ := os.ReadFile(m.Layout.ConfigPath("app"))
			if strings.Contains(string(body), "proxy_cache") {
				t.Errorf("cleared proxy left cache directives:\n%s", body)
			}
			if _, err := os.Stat(mustCacheTablePath(t, m)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cache table survived the last cached proxy (err = %v)", err)
			}
			if _, err := os.Stat(m.cacheDirFor("app")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cached bytes survived the clear (err = %v)", err)
			}
		})
	}
}

func TestProxyCacheClearRemovesRowAndBytes(t *testing.T) {
	m, _ := newLimitsManager(t)
	for _, name := range []string{"api-one", "api-two"} {
		if _, err := m.Create(Spec{Name: name, Domains: []string{name + ".example.com"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.SetProxy(name, "http://127.0.0.1:3000", false); err != nil {
			t.Fatal(err)
		}
		if _, err := m.SetProxyCache(name, &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(m.cacheDirFor("api-one"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := m.SetProxyCache("api-one", nil)
	if err != nil || s.ProxyCache != nil {
		t.Fatalf("clear = %+v, %v", s.ProxyCache, err)
	}
	table, _ := os.ReadFile(mustCacheTablePath(t, m))
	if strings.Contains(string(table), "mp_api_one_cache") {
		t.Errorf("cleared site kept its zone row:\n%s", table)
	}
	if !strings.Contains(string(table), "mp_api_two_cache") {
		t.Errorf("the other site's row disappeared:\n%s", table)
	}
	if _, err := os.Stat(m.cacheDirFor("api-one")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cached bytes survived explicit clear")
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("api-one"))
	if strings.Contains(string(body), "proxy_cache ") {
		t.Errorf("cleared vhost still applies cache:\n%s", body)
	}
	if !strings.Contains(string(body), "proxy_pass http://127.0.0.1:3000;") {
		t.Errorf("clearing the cache removed the proxy itself:\n%s", body)
	}
}

func TestDeleteRemovesCacheRowTableAndBytes(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.cacheDirFor("app"), 0o755); err != nil {
		t.Fatal(err)
	}
	tablePath := mustCacheTablePath(t, m)
	if _, err := m.Delete("app"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(tablePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache table left behind after deleting the last cached site")
	}
	if _, err := os.Stat(m.cacheDirFor("app")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cached bytes left behind after delete")
	}
}

func TestSetProxyCacheRollsBackBothFiles(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	beforeTable, _ := os.ReadFile(mustCacheTablePath(t, m))
	for _, fail := range []string{"-t", "reload"} {
		rec.cmds = nil
		rec.failOn = fail
		_, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 120, MaxSizeMB: 200, InactiveMinutes: 20})
		if !errors.Is(err, ErrConfigRejected) {
			t.Fatalf("failed SetProxyCache (%s) err = %v, want ErrConfigRejected", fail, err)
		}
		after, _ := os.ReadFile(m.Layout.ConfigPath("app"))
		afterTable, _ := os.ReadFile(mustCacheTablePath(t, m))
		if string(after) != string(before) || string(afterTable) != string(beforeTable) {
			t.Errorf("%s failure not rolled back\nvhost:\n%s\ntable:\n%s", fail, after, afterTable)
		}
		rec.failOn = ""
	}
	// A failed clear must not delete the cached bytes either.
	if err := os.MkdirAll(m.cacheDirFor("app"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec.failOn = "-t"
	if _, err := m.SetProxyCache("app", nil); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed clear err = %v", err)
	}
	if _, err := os.Stat(m.cacheDirFor("app")); err != nil {
		t.Errorf("failed clear deleted cached bytes: %v", err)
	}
}

func TestSetProxyCacheRefusesForeignTable(t *testing.T) {
	m, rec := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatal(err)
	}
	tablePath := mustCacheTablePath(t, m)
	if err := os.MkdirAll(filepath.Dir(tablePath), 0o755); err != nil {
		t.Fatal(err)
	}
	const foreign = "proxy_cache_path /var/cache/someone levels=1:2 keys_zone=other:10m max_size=1g;\n"
	if err := os.WriteFile(tablePath, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	rec.cmds = nil
	_, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("cache over foreign table err = %v, want ErrInvalid", err)
	}
	if b, _ := os.ReadFile(tablePath); string(b) != foreign {
		t.Errorf("foreign table overwritten:\n%s", b)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if string(after) != string(before) || len(rec.cmds) != 0 {
		t.Errorf("refused write touched vhost or ran nginx: %v", rec.cmds)
	}
}

func TestProxyCacheRefusesWithoutHttpInclude(t *testing.T) {
	m, rec := newTestManager(t) // no nginx.conf wildcard include
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatal(err)
	}
	rec.cmds = nil
	_, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "include") {
		t.Fatalf("no-include cache err = %v, want ErrInvalid mentioning the include", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx invoked for refused cache: %v", rec.cmds)
	}
	// Unrelated writes must keep working on such a host.
	if _, err := m.SetProxy("app", "", false); err != nil {
		t.Errorf("clearing proxy now requires the include: %v", err)
	}
	if _, err := m.Delete("app"); err != nil {
		t.Errorf("deleting a never-cached site now requires the include: %v", err)
	}
}

func TestMarkerRejectsBadProxyCache(t *testing.T) {
	base := `{"name":"app","domains":["app.example.com"],"root":"/tmp/app","created_at":"2026-01-01T00:00:00Z"`
	cases := []string{
		// Cache without any proxy owner.
		base + `,"proxy_cache":{"valid_seconds":60,"max_size_mb":100,"inactive_minutes":10}}`,
		// Out-of-range numbers beside a valid proxy.
		base + `,"proxy_target":"http://127.0.0.1:3000","proxy_cache":{"valid_seconds":0,"max_size_mb":100,"inactive_minutes":10}}`,
		base + `,"proxy_target":"http://127.0.0.1:3000","proxy_cache":{"valid_seconds":60,"max_size_mb":1,"inactive_minutes":10}}`,
	}
	for _, payload := range cases {
		if _, ok := parseMarker(headerLine + "\n" + markerLine + payload + "\n"); ok {
			t.Errorf("parseMarker accepted invalid cache marker: %s", payload)
		}
	}
	p, ok := parseMarker(headerLine + "\n" + markerLine + base +
		`,"proxy_target":"http://127.0.0.1:3000","proxy_cache":{"valid_seconds":60,"max_size_mb":100,"inactive_minutes":10}}` + "\n")
	if !ok || p.ProxyCache == nil || p.ProxyCache.ValidSeconds != 60 {
		t.Errorf("valid cache marker rejected or lost: %+v, %v", p.ProxyCache, ok)
	}
}

func TestProxyCacheCoexistsWithServerFeatures(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetLimits("app", TrafficLimit{RequestRate: "50r/s"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetCors("app", CorsSettings{Origins: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	for _, want := range []string{
		"proxy_pass http://127.0.0.1:3000;",
		"proxy_set_header Upgrade $http_upgrade;",
		"limit_req zone=mp_app_req;",
		"Access-Control-Allow-Origin",
		"proxy_cache mp_app_cache;",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("combined site lost %q:\n%s", want, body)
		}
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].ProxyCache == nil || list[0].Limits == nil || list[0].Cors == nil {
		t.Errorf("marker after combined writes = %+v", list)
	}
}

// TestProxyCachePreparesWorkerReachableRoot pins what real nginx exposed:
// nginx creates each site's leaf cache directory itself but neither creates
// missing parents nor traverses a 0700 ancestor, and the panel's footprint
// directories are created 0700. Enabling a cache must create the root and add
// only the two execute bits to closed ancestors — never read or write.
func TestProxyCachePreparesWorkerReachableRoot(t *testing.T) {
	m, _ := newLimitsManager(t)
	base := t.TempDir() // 0700, like the panel's own footprint dirs
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	m.CacheDir = filepath.Join(base, "var", "cache", "minipanel")
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if _, err := m.SetProxyCache("app", &ProxyCache{ValidSeconds: 60, MaxSizeMB: 100, InactiveMinutes: 10}); err != nil {
		t.Fatalf("SetProxyCache: %v", err)
	}
	fi, err := os.Stat(m.CacheDir)
	if err != nil {
		t.Fatalf("cache root not created: %v", err)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("cache root mode = %o, want 755", fi.Mode().Perm())
	}
	fi, err = os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o711 {
		t.Errorf("closed ancestor mode = %o, want 711 (execute added, listings still private)", fi.Mode().Perm())
	}
	// Clearing must not touch the root itself, only the site's bytes.
	if _, err := m.SetProxyCache("app", nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := os.Stat(m.CacheDir); err != nil {
		t.Errorf("clear removed the shared cache root: %v", err)
	}
}

func mustCacheTablePath(t *testing.T, m *Manager) string {
	t.Helper()
	p, err := m.cacheTablePath()
	if err != nil {
		t.Fatalf("cacheTablePath: %v", err)
	}
	return p
}
