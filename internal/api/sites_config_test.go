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

// The guarded config editor reads and replaces the whole vhost body. These
// tests pin the read/write round-trip, audit contents, provider errors,
// capability gating, CSRF and malformed bodies.

func TestSiteConfigReadAndWriteAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	fs.configs = map[string]string{"shop": "# minipanel-site: {}\nserver { listen 80; }\n"}

	r, body := p.do(http.MethodGet, "/api/v1/sites/shop/config", "", p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("get config = %d %s", r.StatusCode, body)
	}
	var cfg platform.SiteConfigInfo
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("config json: %v\n%s", err, body)
	}
	if cfg.Name != "shop" || cfg.Content != fs.configs["shop"] || cfg.Path == "" {
		t.Errorf("read = %+v", cfg)
	}
	if fs.configReads != 1 {
		t.Errorf("provider reads = %d, want 1", fs.configReads)
	}

	edited := cfg.Content + "# manual note\n"
	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/config",
		`{"content":`+jsonString(edited)+`}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("put config = %d %s", r.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("put json: %v", err)
	}
	if cfg.Content != edited || fs.configs["shop"] != edited || fs.configWrites != 1 {
		t.Errorf("write round-trip = %+v, stored %q, writes %d", cfg, fs.configs["shop"], fs.configWrites)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/config" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/config") {
			t.Errorf("audit target = %q", e.Target)
		}
	}
	if !found {
		t.Errorf("config write missing from the audit trail")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestSiteConfigMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：标记行不能修改", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_config"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.configErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/config", `{"content":"server {}\n"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("put err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
	// GET maps the same missing/invalid/internal errors (no nginx_rejected on reads).
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	fs.configErr = platform.ErrSiteMissing
	if r, body := p.do(http.MethodGet, "/api/v1/sites/shop/config", "", p.csrfHeader()); r.StatusCode != http.StatusNotFound ||
		!strings.Contains(body, `"kind":"not_found"`) {
		t.Errorf("get missing = %d %s", r.StatusCode, body)
	}
}

func TestSiteConfigGateAndCSRF(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodGet, "/api/v1/sites/shop/config", "", p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("get with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.configReads != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	// Site capability available but the provider lacks the editor interface:
	// 403 capability with the backend reason, never a dead editor.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/config", `{"content":"server {}\n"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "配置文件编辑") {
		t.Errorf("no editor interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.configWrites != 0 {
		t.Error("provider called without the editor interface")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/config", `{"content":"x"}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("put without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.configWrites != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteConfigBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/config", `{"content":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.configWrites != 0 {
		t.Error("provider called with a malformed body")
	}
}
