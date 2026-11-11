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

// The proxy endpoint accepts one upstream URL, not a config snippet. These
// tests pin the HTTP contract: validated fields round-trip, clearing works,
// provider errors keep their identity, and a host without the optional
// interface refuses the route with the bitmap's reason.

func TestSiteProxyUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy",
		`{"target":"http://127.0.0.1:3000","websocket":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("proxy = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("proxy json: %v\n%s", err, body)
	}
	if site.ProxyTarget != "http://127.0.0.1:3000" || !site.ProxyWebSocket {
		t.Errorf("response proxy = %+v", site)
	}
	if fs.proxySets != 1 || fs.sites["app"].ProxyTarget != "http://127.0.0.1:3000" {
		t.Errorf("provider counters = %d, stored = %+v", fs.proxySets, fs.sites["app"])
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/proxy" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/app/proxy") {
				t.Errorf("audit target = %q", e.Target)
			}
		}
	}
	if !found {
		t.Errorf("proxy change missing from the audit trail")
	}
}

func TestSiteProxyClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy",
		`{"target":"http://127.0.0.1:3000"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set proxy = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy",
		`{"target":"","websocket":false}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear proxy = %d %s", r.StatusCode, body)
	}
	if fs.sites["app"].ProxyTarget != "" || fs.sites["app"].ProxyWebSocket {
		t.Errorf("proxy not cleared: %+v", fs.sites["app"])
	}
	if fs.proxySets != 2 {
		t.Errorf("provider saw %d proxy writes, want 2", fs.proxySets)
	}
}

func TestSiteProxyMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：代理目标必须以 http:// 开头", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_proxy"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "app")
		fs.proxyErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy",
			`{"target":"http://127.0.0.1:3000"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteProxyGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy",
		`{"target":"http://127.0.0.1:3000"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("proxy with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.proxySets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/app/proxy",
		`{"target":"http://127.0.0.1:3000"}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("proxy without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.proxySets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteProxyRejectsBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "app")
	r, body := p.do(http.MethodPut, "/api/v1/sites/app/proxy", `{not json`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
}
