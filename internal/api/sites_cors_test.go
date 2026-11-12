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

// The CORS policy replaces the whole structured policy in one PUT. These
// tests pin request/response round-trips, audit contents, provider errors,
// capability gating, CSRF and malformed bodies.

func TestSiteCorsUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "api")
	r, body := p.do(http.MethodPut, "/api/v1/sites/api/cors",
		`{"origins":["https://app.example.com"],"methods":["GET","POST"],"headers":["Content-Type"],"credentials":true,"max_age":600}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("cors = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("cors json: %v\n%s", err, body)
	}
	if site.Cors == nil || len(site.Cors.Origins) != 1 || site.Cors.Origins[0] != "https://app.example.com" ||
		!site.Cors.Credentials || site.Cors.MaxAge != 600 {
		t.Errorf("response cors = %+v", site.Cors)
	}
	if fs.corsSets != 1 || fs.sites["api"].Cors == nil {
		t.Errorf("provider counters = %d, stored = %+v", fs.corsSets, fs.sites["api"].Cors)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/cors" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/api/cors") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "app.example.com") {
			t.Errorf("audit lost cors origins: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("cors change missing from the audit trail")
	}
}

func TestSiteCorsClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "api")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/api/cors",
		`{"origins":["*"]}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set cors = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/api/cors", `{"origins":[]}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear cors = %d %s", r.StatusCode, body)
	}
	if fs.sites["api"].Cors != nil {
		t.Errorf("cors not cleared: %+v", fs.sites["api"].Cors)
	}
	if fs.corsSets != 2 {
		t.Errorf("provider saw %d writes, want 2", fs.corsSets)
	}
}

func TestSiteCorsMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：通配符 * 不能与其它来源混用", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_cors"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "api")
		fs.corsErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/api/cors", `{"origins":["*"]}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteCorsGateAndCSRF(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/api/cors", `{"origins":["*"]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("cors with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.corsSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	// Site capability available but the provider lacks the CORS interface:
	// 403 capability with the backend reason, never a dead write.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.do(http.MethodPut, "/api/v1/sites/api/cors", `{"origins":["*"]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "CORS") {
		t.Errorf("no cors interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.corsSets != 0 {
		t.Error("provider called without the cors interface")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "api")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/api/cors", `{"origins":[]}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("cors without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.corsSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteCorsBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "api")
	r, body := p.do(http.MethodPut, "/api/v1/sites/api/cors", `{"origins":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.corsSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
