package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// 第廿五片 adds PUT /sites/{name}/proxy-cache: one nullable policy object,
// nil clears it. The write discipline, ownership coupling (enable needs a
// proxy, clearing the proxy drops the cache) and the two-file transaction are
// pinned in internal/nginx; here the HTTP contract is pinned: round-trip,
// audit contents, provider error mapping, capability gating, CSRF, bad JSON.

func TestSiteProxyCacheUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy",
		`{"target":"http://127.0.0.1:8081","websocket":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set proxy = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache",
		`{"cache":{"valid_seconds":60,"max_size_mb":512,"inactive_minutes":30}}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("proxy-cache = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("proxy-cache json: %v\n%s", err, body)
	}
	if site.ProxyCache == nil || site.ProxyCache.ValidSeconds != 60 ||
		site.ProxyCache.MaxSizeMB != 512 || site.ProxyCache.InactiveMinutes != 30 {
		t.Errorf("response cache = %+v", site.ProxyCache)
	}
	if fs.proxyCacheSets != 1 || fs.sites["shop"].ProxyCache == nil {
		t.Errorf("provider counters = %d, stored = %+v", fs.proxyCacheSets, fs.sites["shop"].ProxyCache)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/proxy-cache" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/proxy-cache") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "valid_seconds") {
			t.Errorf("audit lost cache policy: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("cache change missing from the audit trail")
	}
}

func TestSiteProxyCacheClearAndProxyCoupling(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")

	// Enabling on a static site is the provider's refusal, passed through as
	// 400 invalid_site with the backend sentence — never a silent success.
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache",
		`{"cache":{"valid_seconds":60,"max_size_mb":512,"inactive_minutes":30}}`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"invalid_site"`) || !strings.Contains(body, "反向代理") {
		t.Errorf("cache on static site = %d %s, want 400 invalid_site with reason", r.StatusCode, body)
	}

	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy",
		`{"target":"http://127.0.0.1:8081","websocket":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set proxy = %d %s", r.StatusCode, body)
	}
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache",
		`{"cache":{"valid_seconds":60,"max_size_mb":512,"inactive_minutes":30}}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set cache = %d %s", r.StatusCode, body)
	}

	// Explicit clear keeps the proxy but drops the policy.
	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache", `{"cache":null}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear cache = %d %s", r.StatusCode, body)
	}
	s := fs.sites["shop"]
	if s.ProxyCache != nil || s.ProxyTarget == "" {
		t.Errorf("clear kept proxy but dropped cache? stored = %+v", s)
	}

	// Clearing the proxy itself drops the cache in the same call.
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache",
		`{"cache":{"valid_seconds":60,"max_size_mb":512,"inactive_minutes":30}}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("re-set cache = %d %s", r.StatusCode, body)
	}
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy",
		`{"target":"","websocket":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("clear proxy = %d %s", r.StatusCode, body)
	}
	s = fs.sites["shop"]
	if s.ProxyCache != nil || s.ProxyTarget != "" {
		t.Errorf("clearing proxy must drop the cache too: %+v", s)
	}
}

func TestSiteProxyCacheMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：缓存时间必须在 1-2592000 秒之间", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_proxy_cache"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.proxyCacheErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache", `{"cache":null}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteProxyCacheGateAndCSRF(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache", `{"cache":null}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("cache with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.proxyCacheSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	// Site capability available but the provider lacks the cache interface:
	// 403 capability with the backend reason, never a dead write.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache", `{"cache":null}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "缓存") {
		t.Errorf("no cache interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.proxyCacheSets != 0 {
		t.Error("provider called without the cache interface")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache", `{"cache":null}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("cache without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.proxyCacheSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteProxyCacheBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/proxy-cache", `{"cache":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.proxyCacheSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
