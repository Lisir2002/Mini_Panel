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

// The rewrite endpoint is a closed vocabulary, not a config editor. These tests
// pin the HTTP half: the selector is served by the provider, the write is
// audited, unknown/PHP-dependent templates keep their error identity, and a
// host without a site writer refuses both routes with the bitmap's reason.

func TestSiteRewritePresets(t *testing.T) {
	p, fs := newSitePanel(t, true)
	r, body := p.get("/api/v1/sites/rewrite-presets")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("presets = %d %s", r.StatusCode, body)
	}
	var resp struct {
		Items []platform.RewritePreset `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("presets json: %v\n%s", err, body)
	}
	if len(resp.Items) != 3 || resp.Items[1].ID != "wordpress" || !resp.Items[1].RequiresPHP {
		t.Errorf("preset list = %+v", resp.Items)
	}
	if fs.rewriteSets != 0 {
		t.Error("GET presets wrote something")
	}
}

func TestSiteRewriteUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPut, "/api/v1/sites/blog/rewrite",
		`{"preset":"wordpress"}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("rewrite = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("rewrite json: %v\n%s", err, body)
	}
	if site.Rewrite != "wordpress" {
		t.Errorf("response rewrite = %q, want wordpress", site.Rewrite)
	}
	if fs.rewriteSets != 1 || fs.sites["blog"].Rewrite != "wordpress" {
		t.Errorf("provider counters = %d, stored = %q", fs.rewriteSets, fs.sites["blog"].Rewrite)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/rewrite" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/blog/rewrite") {
				t.Errorf("audit target = %q", e.Target)
			}
		}
	}
	if !found {
		t.Errorf("rewrite change missing from the audit trail")
	}
}

func TestSiteCreateWithRewrite(t *testing.T) {
	p, fs := newSitePanel(t, true)
	r, body := p.do(http.MethodPost, "/api/v1/sites",
		`{"name":"blog","domains":["blog.example.com"],"rewrite":"spa"}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("create json: %v\n%s", err, body)
	}
	if site.Rewrite != "spa" || fs.sites["blog"].Rewrite != "spa" {
		t.Errorf("created rewrite = %q, stored = %q", site.Rewrite, fs.sites["blog"].Rewrite)
	}
}

func TestSiteRewriteMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：需要先绑定 PHP", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_rewrite"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "blog")
		fs.rewriteErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/blog/rewrite",
			`{"preset":"wordpress"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteRewriteGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	for _, req := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/sites/rewrite-presets", ""},
		{http.MethodPut, "/api/v1/sites/blog/rewrite", `{"preset":"none"}`},
	} {
		r, body := p.do(req.method, req.path, req.body, p.csrfHeader())
		if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
			t.Errorf("%s %s = %d %s, want 403 capability", req.method, req.path, r.StatusCode, body)
		}
	}
	if fs.rewriteSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, _ := p.do(http.MethodPut, "/api/v1/sites/blog/rewrite",
		`{"preset":"none"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("rewrite without csrf = %d, want 403", r.StatusCode)
	}
	if fs.rewriteSets != 0 {
		t.Error("provider called without CSRF")
	}
}
