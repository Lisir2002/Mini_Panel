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

// The hotlink endpoint toggles one fixed Referer check. These tests pin the HTTP
// contract: the two flags round-trip, disabling clears them, provider errors keep
// their identity, and a host without the optional interface refuses the route
// with the bitmap's reason.

func TestSiteHotlinkUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/hotlink",
		`{"enabled":true,"allow_empty":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("hotlink = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("hotlink json: %v\n%s", err, body)
	}
	if !site.Hotlink || !site.HotlinkAllowEmpty {
		t.Errorf("response hotlink = %+v", site)
	}
	if fs.hotlinkSets != 1 || !fs.sites["old"].Hotlink || !fs.sites["old"].HotlinkAllowEmpty {
		t.Errorf("provider counters = %d, stored = %+v", fs.hotlinkSets, fs.sites["old"])
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/hotlink" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/old/hotlink") {
				t.Errorf("audit target = %q", e.Target)
			}
		}
	}
	if !found {
		t.Errorf("hotlink change missing from the audit trail")
	}
}

func TestSiteHotlinkDisable(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/old/hotlink",
		`{"enabled":true,"allow_empty":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set hotlink = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/hotlink",
		`{"enabled":false,"allow_empty":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("disable hotlink = %d %s", r.StatusCode, body)
	}
	if fs.sites["old"].Hotlink || fs.sites["old"].HotlinkAllowEmpty {
		t.Errorf("hotlink not disabled: %+v", fs.sites["old"])
	}
	if fs.hotlinkSets != 2 {
		t.Errorf("provider saw %d hotlink writes, want 2", fs.hotlinkSets)
	}
}

func TestSiteHotlinkMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：站点正在使用反向代理", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_hotlink"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "old")
		fs.hotlinkErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/old/hotlink",
			`{"enabled":true,"allow_empty":true}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteHotlinkGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/hotlink",
		`{"enabled":true,"allow_empty":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("hotlink with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.hotlinkSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/old/hotlink",
		`{"enabled":true,"allow_empty":true}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("hotlink without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.hotlinkSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteHotlinkRejectsBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/hotlink", `{not json`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
}
