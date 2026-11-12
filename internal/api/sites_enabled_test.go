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

// 第廿三片 adds PUT /sites/{name}/enabled. The layout mechanism (symlink vs
// parking directory) and its rollback are pinned in internal/nginx; what is
// asserted here is the HTTP contract: round-trip + audit, error mapping,
// capability gating, CSRF and malformed bodies.

func TestSiteEnabledToggleAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	s := fs.sites["shop"]
	s.Enabled = true
	fs.sites["shop"] = s

	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":false}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("stop = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("stop json: %v\n%s", err, body)
	}
	if site.Enabled {
		t.Errorf("response still enabled")
	}
	if fs.enableSets != 1 || fs.sites["shop"].Enabled {
		t.Errorf("provider counter = %d, stored enabled = %v", fs.enableSets, fs.sites["shop"].Enabled)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/enabled" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/enabled") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "enabled") {
			t.Errorf("audit lost the enabled value: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("stop missing from the audit trail")
	}

	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("start = %d %s", r.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("start json: %v", err)
	}
	if !site.Enabled || !fs.sites["shop"].Enabled || fs.enableSets != 2 {
		t.Errorf("start round-trip = %+v, counter %d", site, fs.enableSets)
	}
}

func TestSiteEnabledMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：站点名不合法", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_enabled"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.enableErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":false}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteEnabledGateAndCSRF(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":false}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.enableSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	// Site capability available but the provider lacks the switch interface:
	// 403 capability with the backend reason, never a dead toggle.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":false}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "停用/启用") {
		t.Errorf("no switch interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.enableSets != 0 {
		t.Error("provider called without the switch interface")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":false}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("put without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.enableSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteEnabledBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/enabled", `{"enabled":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.enableSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
