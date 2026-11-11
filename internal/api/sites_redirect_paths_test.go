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

// The per-path redirect table replaces the entire table in one PUT. These
// tests pin request/response round-trips, audit contents, provider errors,
// capability gating, CSRF and malformed bodies.

func TestSiteRedirectPathsUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths",
		`{"rules":[{"path":"/news","target":"https://new.example.com/articles","code":301},{"path":"/old","target":"https://archive.example.com","code":302}]}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("redirect-paths = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("redirect-paths json: %v\n%s", err, body)
	}
	if len(site.RedirectPaths) != 2 || site.RedirectPaths[0].Path != "/news" ||
		site.RedirectPaths[1].Target != "https://archive.example.com" || site.RedirectPaths[1].Code != 302 {
		t.Errorf("response redirect paths = %+v", site.RedirectPaths)
	}
	if fs.redirectPathSets != 1 || len(fs.sites["old"].RedirectPaths) != 2 {
		t.Errorf("provider counters = %d, stored = %+v", fs.redirectPathSets, fs.sites["old"].RedirectPaths)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/redirect-paths" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/old/redirect-paths") {
			t.Errorf("audit target = %q", e.Target)
		}
		// Audit values are flattened and long ones truncated before storage;
		// this still proves both paths and at least one target reached audit.
		if !strings.Contains(e.Params, "/news") || !strings.Contains(e.Params, "/old") ||
			!strings.Contains(e.Params, "https://new.example.com/articles") {
			t.Errorf("audit lost redirect rules: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("redirect-path change missing from the audit trail")
	}
}

func TestSiteRedirectPathsClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths",
		`{"rules":[{"path":"/old","target":"https://new.example.com","code":301}]}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set redirect paths = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths", `{"rules":[]}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear redirect paths = %d %s", r.StatusCode, body)
	}
	if len(fs.sites["old"].RedirectPaths) != 0 {
		t.Errorf("redirect paths not cleared: %+v", fs.sites["old"].RedirectPaths)
	}
	if fs.redirectPathSets != 2 {
		t.Errorf("provider saw %d writes, want 2", fs.redirectPathSets)
	}
}

func TestSiteRedirectPathsMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：第 1 条路径只能以 / 开头", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_redirect_paths"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "old")
		fs.redirectPathErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths",
			`{"rules":[{"path":"/old","target":"https://new.example.com","code":301}]}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteRedirectPathsGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths",
		`{"rules":[{"path":"/old","target":"https://new.example.com","code":301}]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("redirect-paths with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.redirectPathSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths",
		`{"rules":[]}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("redirect-paths without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.redirectPathSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteRedirectPathsBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "old")
	r, body := p.do(http.MethodPut, "/api/v1/sites/old/redirect-paths", `{"rules":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.redirectPathSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
