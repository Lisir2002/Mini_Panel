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

// The load-balanced proxy table replaces the entire backend list in one PUT.
// These tests pin request/response round-trips, the handover with the
// single-target form, audit contents, provider errors, capability gating,
// CSRF and malformed bodies.

func TestSiteProxyUpstreamsUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams",
		`{"upstreams":[{"target":"http://127.0.0.1:3000","weight":3},{"target":"http://127.0.0.1:3001"}],"method":"least_conn","websocket":true}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("proxy-upstreams = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("proxy-upstreams json: %v\n%s", err, body)
	}
	if len(site.ProxyUpstreams) != 2 || site.ProxyUpstreams[0].Weight != 3 ||
		site.ProxyLBMethod != "least_conn" || !site.ProxyWebSocket {
		t.Errorf("response upstreams = %+v method=%q ws=%v", site.ProxyUpstreams, site.ProxyLBMethod, site.ProxyWebSocket)
	}
	if fs.proxyLBSets != 1 || len(fs.sites["app"].ProxyUpstreams) != 2 {
		t.Errorf("provider counters = %d, stored = %+v", fs.proxyLBSets, fs.sites["app"].ProxyUpstreams)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/proxy-upstreams" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/app/proxy-upstreams") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "127.0.0.1:3000") || !strings.Contains(e.Params, "least_conn") {
			t.Errorf("audit lost upstream rules: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("upstream change missing from the audit trail")
	}
}

func TestSiteProxyUpstreamsHandOverWithSingleTarget(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy",
		`{"target":"http://127.0.0.1:9000","websocket":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set single proxy = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams",
		`{"upstreams":[{"target":"http://127.0.0.1:3000"}],"method":"","websocket":false}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("set upstreams = %d %s", r.StatusCode, body)
	}
	s := fs.sites["app"]
	if s.ProxyTarget != "" || len(s.ProxyUpstreams) != 1 {
		t.Errorf("handover left both forms: %+v", s)
	}
}

func TestSiteProxyUpstreamsClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams",
		`{"upstreams":[{"target":"http://127.0.0.1:3000"}],"method":"ip_hash","websocket":true}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set upstreams = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams", `{"upstreams":[]}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear upstreams = %d %s", r.StatusCode, body)
	}
	s := fs.sites["app"]
	if len(s.ProxyUpstreams) != 0 || s.ProxyLBMethod != "" || s.ProxyWebSocket {
		t.Errorf("upstreams not cleared: %+v", s)
	}
	if fs.proxyLBSets != 2 {
		t.Errorf("provider saw %d writes, want 2", fs.proxyLBSets)
	}
}

func TestSiteProxyUpstreamsMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：第 1 个后端必须以 http:// 开头", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_proxy_upstreams"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "app")
		fs.proxyLBErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams",
			`{"upstreams":[{"target":"http://127.0.0.1:3000"}]}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteProxyUpstreamsGateAndCSRF(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams",
		`{"upstreams":[{"target":"http://127.0.0.1:3000"}]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("proxy-upstreams with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.proxyLBSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	// Site capability available but the provider lacks the load-balanced
	// interface: 403 capability with the backend reason, never a dead write.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams",
		`{"upstreams":[{"target":"http://127.0.0.1:3000"}]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "负载均衡") {
		t.Errorf("no LB interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.proxyLBSets != 0 {
		t.Error("provider called without the load-balanced interface")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams", `{"upstreams":[]}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("proxy-upstreams without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.proxyLBSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteProxyUpstreamsBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy-upstreams", `{"upstreams":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.proxyLBSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
