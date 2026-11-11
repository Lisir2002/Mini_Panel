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

// The PHP switch is the site-level half of M2. These tests pin the HTTP
// contract around it: a version can be chosen at create time or changed later,
// clearing is always possible, a version choice is gated by the bitmap, and the
// write joins the audit trail. The nginx rendering and the "does this version
// really have fpm" check are pinned in internal/nginx and internal/platform.

func TestSiteCreateWithPHPVersion(t *testing.T) {
	p, fs := newSitePanel(t, true)
	r, body := p.do(http.MethodPost, "/api/v1/sites",
		`{"name":"blog","domains":["blog.example.com"],"php_version":"8.3"}`, p.csrfHeader())
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("create json: %v\n%s", err, body)
	}
	if site.PHPVersion != "8.3" || site.PHPSocket != "/run/php/php8.3-fpm.sock" {
		t.Errorf("created php = %+v", site)
	}
	if site.PHPSocketState != "listening" {
		t.Errorf("socket state = %q, want listening", site.PHPSocketState)
	}
	if fs.created != 1 {
		t.Errorf("provider creates = %d, want 1", fs.created)
	}
}

func TestSitePHPSwitchAndClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPut, "/api/v1/sites/blog/php",
		`{"php_version":"8.3"}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("switch = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("switch json: %v\n%s", err, body)
	}
	if site.PHPVersion != "8.3" || site.PHPSocketState != "listening" {
		t.Errorf("switch row = %+v", site)
	}
	if fs.phpSets != 1 || fs.phpClears != 0 {
		t.Errorf("provider counters after switch: sets=%d clears=%d", fs.phpSets, fs.phpClears)
	}

	r, body = p.do(http.MethodPut, "/api/v1/sites/blog/php",
		`{"php_version":""}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear = %d %s", r.StatusCode, body)
	}
	site = platform.SiteInfo{}
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("clear json: %v\n%s", err, body)
	}
	if site.PHPVersion != "" || site.PHPSocket != "" {
		t.Errorf("clear left a binding: %+v", site)
	}
	if fs.phpSets != 2 || fs.phpClears != 1 {
		t.Errorf("provider counters after clear: sets=%d clears=%d", fs.phpSets, fs.phpClears)
	}
}

func TestSitePHPGateAndCreateGate(t *testing.T) {
	fs := newFakeSites()
	caps := siteCaps(true, "")
	reason := "本机没有 php-fpm 后端"
	caps.Features[platform.FeatPHPVersionSwitch] = platform.Feature{
		State: platform.StateUnavailable, Reason: reason,
	}
	p := newPanelWith(t, nil, fakeSitePlatform{t: t, site: fs, ready: true}, caps)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	seedSite(t, p, fs, "blog")

	r, body := p.do(http.MethodPut, "/api/v1/sites/blog/php",
		`{"php_version":"8.3"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Fatalf("switch with unavailable php = %d %s", r.StatusCode, body)
	}
	if !strings.Contains(body, reason) {
		t.Errorf("refusal does not quote the bitmap: %s", body)
	}
	if fs.phpSets != 0 {
		t.Errorf("provider called while php_version_switch was unavailable")
	}

	// Clearing is a rescue path: a site bound before php-fpm disappeared must
	// still be detachable even though no new version can be selected.
	r, body = p.do(http.MethodPut, "/api/v1/sites/blog/php",
		`{"php_version":""}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear with unavailable php = %d %s", r.StatusCode, body)
	}

	// Create-time selection is gated too, but a static site stays available.
	r, body = p.do(http.MethodPost, "/api/v1/sites",
		`{"name":"phpblog","domains":["php.example.com"],"php_version":"8.3"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, reason) {
		t.Errorf("create with php while unavailable = %d %s", r.StatusCode, body)
	}
	if fs.created != 1 {
		t.Errorf("create reached provider while php was unavailable (created=%d)", fs.created)
	}
	r, body = p.do(http.MethodPost, "/api/v1/sites",
		`{"name":"static","domains":["static.example.com"]}`, p.csrfHeader())
	if r.StatusCode != http.StatusCreated {
		t.Errorf("static create while php unavailable = %d %s", r.StatusCode, body)
	}
}

func TestSitePHPMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：PHP 8.1 没有 fpm 后端", platform.ErrSitePHP), http.StatusUnprocessableEntity, "php_unavailable"},
		{fmt.Errorf("%w：版本号不合法", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_php"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "blog")
		fs.phpErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/blog/php",
			`{"php_version":"8.1"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSitePHPWritesRequireCSRF(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, _ := p.do(http.MethodPut, "/api/v1/sites/blog/php",
		`{"php_version":"8.3"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("switch without csrf = %d, want 403", r.StatusCode)
	}
	if fs.phpSets != 0 {
		t.Errorf("provider called without CSRF")
	}
}

func TestSitePHPWriteIsAudited(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/blog/php",
		`{"php_version":"8.3"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("switch = %d %s", r.StatusCode, body)
	}
	entries, _, err := audit.New(p.st).List(100, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}/php" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/blog/php") {
				t.Errorf("audit target = %q", e.Target)
			}
		}
	}
	if !found {
		t.Errorf("PHP switch missing from the audit trail: %+v", entries)
	}
}
