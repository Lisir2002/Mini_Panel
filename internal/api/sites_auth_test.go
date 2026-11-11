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

// The access-password endpoint is a fixed Basic Auth gate. These tests pin the
// HTTP contract: the username round-trips, the password is neither echoed nor
// stored in the audit trail, clearing works, provider errors keep their
// identity, and a host without the optional interface refuses the route with
// the bitmap's reason.

func TestSiteAuthUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	const password = "Sup3rSecret!pw"
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/auth",
		`{"username":"guest","password":"`+password+`"}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("auth = %d %s", r.StatusCode, body)
	}
	if strings.Contains(body, password) || strings.Contains(body, "{SHA}") {
		t.Errorf("response leaked the password or its hash: %s", body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("auth json: %v\n%s", err, body)
	}
	if site.AuthUser != "guest" {
		t.Errorf("response auth_user = %q", site.AuthUser)
	}
	if fs.authSets != 1 || fs.sites["old"].AuthUser != "guest" {
		t.Errorf("provider counters = %d, stored = %+v", fs.authSets, fs.sites["old"])
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/auth" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/old/auth") {
				t.Errorf("audit target = %q", e.Target)
			}
			if strings.Contains(e.Params, password) {
				t.Errorf("audit stored the password: %q", e.Params)
			}
			if !strings.Contains(e.Params, "password=***") {
				t.Errorf("audit did not mask the password: %q", e.Params)
			}
			if !strings.Contains(e.Params, "username=guest") {
				t.Errorf("audit lost the non-secret username: %q", e.Params)
			}
		}
	}
	if !found {
		t.Errorf("auth change missing from the audit trail")
	}
}

func TestSiteAuthClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/old/auth",
		`{"username":"guest","password":"Sup3rSecret!pw"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set auth = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/auth",
		`{"username":"","password":""}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear auth = %d %s", r.StatusCode, body)
	}
	if fs.sites["old"].AuthUser != "" {
		t.Errorf("auth not cleared: %+v", fs.sites["old"])
	}
	if fs.authSets != 2 {
		t.Errorf("provider saw %d auth writes, want 2", fs.authSets)
	}
}

func TestSiteAuthMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：口令长度需要 8-128 个字符", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_auth"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "old")
		fs.authErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/old/auth",
			`{"username":"guest","password":"Sup3rSecret!pw"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteAuthGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/auth",
		`{"username":"guest","password":"Sup3rSecret!pw"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("auth with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.authSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/old/auth",
		`{"username":"guest","password":"Sup3rSecret!pw"}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("auth without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.authSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteAuthBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/auth", `{"username":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.authSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
