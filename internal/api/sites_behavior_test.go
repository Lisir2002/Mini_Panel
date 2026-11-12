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

// 第十七片 adds two PUT endpoints that flip a boolean. The HTTP layer is thin
// (gate, decode, map the provider result or error), so these tests pin exactly
// that: round-trip + audit, the force-HTTPS precondition surfacing as 400, error
// mapping, capability gating + CSRF, and malformed bodies. The directive itself
// is pinned in internal/nginx.

func TestSiteAutoIndexSetClearAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/autoindex", `{"enabled":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("autoindex = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("autoindex json: %v\n%s", err, body)
	}
	if !site.AutoIndex {
		t.Errorf("response autoindex = false")
	}
	if fs.autoIndexSets != 1 || !fs.sites["shop"].AutoIndex {
		t.Errorf("provider counter = %d, stored = %+v", fs.autoIndexSets, fs.sites["shop"].AutoIndex)
	}
	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/autoindex" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/autoindex") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "enabled") {
			t.Errorf("audit lost the autoindex value: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("autoindex change missing from the audit trail")
	}

	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/autoindex", `{"enabled":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("clear autoindex = %d %s", r.StatusCode, body)
	}
	if fs.sites["shop"].AutoIndex {
		t.Errorf("autoindex not cleared")
	}
}

func TestSiteForceHTTPSRequiresTLSThenToggles(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	// No certificate yet: forcing HTTPS is refused with a reason, not silently
	// written — this is the honest refusal that keeps the UI from a dead toggle.
	if r, body := p.do(http.MethodPut, "/api/v1/sites/blog/force-https", `{"enabled":true}`, p.csrfHeader()); r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"invalid_site"`) {
		t.Fatalf("force-https without TLS = %d %s", r.StatusCode, body)
	}
	if fs.forceHTTPSSets != 0 {
		t.Errorf("provider saw %d writes on a rejected force-https", fs.forceHTTPSSets)
	}
	// Now the site has HTTPS (marked directly, mirroring what the TLS endpoints
	// would store on the row).
	s := fs.sites["blog"]
	s.TLS = &platform.SiteTLSInfo{Enabled: true}
	fs.sites["blog"] = s

	r, body := p.do(http.MethodPut, "/api/v1/sites/blog/force-https", `{"enabled":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("force-https on TLS site = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("force-https json: %v", err)
	}
	if site.TLS == nil || !site.TLS.Redirect {
		t.Errorf("response tls.redirect = %+v", site.TLS)
	}

	if r, body := p.do(http.MethodPut, "/api/v1/sites/blog/force-https", `{"enabled":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("disable force-https = %d %s", r.StatusCode, body)
	}
	if fs.sites["blog"].TLS == nil || fs.sites["blog"].TLS.Redirect {
		t.Errorf("force-https not cleared: %+v", fs.sites["blog"].TLS)
	}
}

func TestSiteBehaviorMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：强制 HTTPS 需要先为该站点启用 HTTPS", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] unknown directive", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_autoindex"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.behaviorErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/autoindex", `{"enabled":true}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteBehaviorGateAndCSRF(t *testing.T) {
	for _, path := range []string{"autoindex", "force-https"} {
		p, fs := newSitePanel(t, false)
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/"+path, `{"enabled":true}`, p.csrfHeader())
		if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
			t.Errorf("%s with site unavailable = %d %s, want 403 capability", path, r.StatusCode, body)
		}
		if fs.autoIndexSets != 0 || fs.forceHTTPSSets != 0 {
			t.Errorf("%s: provider called while site capability unavailable", path)
		}

		p, fs = newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/"+path, `{"enabled":true}`, nil)
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("%s without CSRF = %d, want 403", path, r.StatusCode)
		}
		if fs.autoIndexSets != 0 || fs.forceHTTPSSets != 0 {
			t.Errorf("%s: provider called without CSRF", path)
		}
	}
}

func TestSiteBehaviorBadJSON(t *testing.T) {
	for _, path := range []string{"autoindex", "force-https"} {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/"+path, `{"enabled":`, p.csrfHeader())
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
			t.Errorf("%s bad json = %d %s", path, r.StatusCode, body)
		}
		if fs.autoIndexSets != 0 || fs.forceHTTPSSets != 0 {
			t.Errorf("%s: provider called with a malformed body", path)
		}
	}
}
