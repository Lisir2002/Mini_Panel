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

// The redirect endpoint accepts one validated URL plus 301/302 and keep-path.
// These tests pin the HTTP contract: fields round-trip, clearing works,
// provider errors keep their identity, and a host without the optional
// interface refuses the route with the bitmap's reason.

func TestSiteRedirectUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect",
		`{"target":"https://new.example.com","code":301,"keep_path":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("redirect = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("redirect json: %v\n%s", err, body)
	}
	if site.RedirectTarget != "https://new.example.com" || site.RedirectCode != 301 || !site.RedirectKeepPath {
		t.Errorf("response redirect = %+v", site)
	}
	if fs.redirectSets != 1 || fs.sites["old"].RedirectTarget != "https://new.example.com" {
		t.Errorf("provider counters = %d, stored = %+v", fs.redirectSets, fs.sites["old"])
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/redirect" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/old/redirect") {
				t.Errorf("audit target = %q", e.Target)
			}
		}
	}
	if !found {
		t.Errorf("redirect change missing from the audit trail")
	}
}

func TestSiteRedirectClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect",
		`{"target":"https://new.example.com","code":302,"keep_path":false}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set redirect = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect",
		`{"target":"","code":0,"keep_path":false}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear redirect = %d %s", r.StatusCode, body)
	}
	if fs.sites["old"].RedirectTarget != "" || fs.sites["old"].RedirectCode != 0 || fs.sites["old"].RedirectKeepPath {
		t.Errorf("redirect not cleared: %+v", fs.sites["old"])
	}
	if fs.redirectSets != 2 {
		t.Errorf("provider saw %d redirect writes, want 2", fs.redirectSets)
	}
}

func TestSiteRedirectMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：跳转目标必须以 http:// 或 https:// 开头", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_redirect"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "old")
		fs.redirectErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect",
			`{"target":"https://new.example.com","code":301}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteRedirectGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect",
		`{"target":"https://new.example.com","code":301}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("redirect with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.redirectSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/old/redirect",
		`{"target":"https://new.example.com","code":301}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("redirect without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.redirectSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteRedirectRejectsBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect", `{not json`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
}
