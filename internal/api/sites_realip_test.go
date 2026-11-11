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

// The real-IP endpoint carries an explicit trust list. These tests pin the HTTP
// contract: the list and header round-trip, clearing works, provider errors
// keep their identity, and a host without the optional interface refuses the
// route with the bitmap's reason.

func TestSiteRealIPUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/realip",
		`{"from":["10.0.0.0/8","192.0.2.7"],"header":"X-Forwarded-For"}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("realip = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("realip json: %v\n%s", err, body)
	}
	if len(site.RealIPFrom) != 2 || site.RealIPFrom[0] != "10.0.0.0/8" || site.RealIPHeader != "X-Forwarded-For" {
		t.Errorf("response real-IP fields = %+v", site)
	}
	if fs.realIPSets != 1 || len(fs.sites["old"].RealIPFrom) != 2 {
		t.Errorf("provider counters = %d, stored = %+v", fs.realIPSets, fs.sites["old"])
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/realip" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/old/realip") {
				t.Errorf("audit target = %q", e.Target)
			}
			if !strings.Contains(e.Params, "10.0.0.0/8") || !strings.Contains(e.Params, "X-Forwarded-For") {
				t.Errorf("audit lost the trust list or header: %q", e.Params)
			}
		}
	}
	if !found {
		t.Errorf("real-IP change missing from the audit trail")
	}
}

func TestSiteRealIPClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/old/realip",
		`{"from":["10.0.0.0/8"],"header":"X-Real-IP"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set realip = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/realip",
		`{"from":[],"header":""}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear realip = %d %s", r.StatusCode, body)
	}
	if len(fs.sites["old"].RealIPFrom) != 0 || fs.sites["old"].RealIPHeader != "" {
		t.Errorf("real IP not cleared: %+v", fs.sites["old"])
	}
	if fs.realIPSets != 2 {
		t.Errorf("provider saw %d real-IP writes, want 2", fs.realIPSets)
	}
}

func TestSiteRealIPMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：不能信任 0.0.0.0/0", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_real_ip"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "old")
		fs.realIPErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/old/realip",
			`{"from":["10.0.0.0/8"],"header":""}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteRealIPGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/realip",
		`{"from":["10.0.0.0/8"],"header":""}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("realip with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.realIPSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/old/realip",
		`{"from":["10.0.0.0/8"],"header":""}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("realip without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.realIPSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteRealIPBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/realip", `{"from":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.realIPSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
