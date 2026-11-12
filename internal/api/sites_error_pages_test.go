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

// The custom error page table replaces the entire table in one PUT. These
// tests pin request/response round-trips, audit contents, provider errors,
// capability gating, CSRF and malformed bodies.

func TestSiteErrorPagesUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/error-pages",
		`{"rules":[{"code":404,"path":"/404.html"},{"code":502,"path":"/50x.html"}]}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("error-pages = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("error-pages json: %v\n%s", err, body)
	}
	if len(site.ErrorPages) != 2 || site.ErrorPages[0].Code != 404 ||
		site.ErrorPages[0].Path != "/404.html" || site.ErrorPages[1].Code != 502 {
		t.Errorf("response error pages = %+v", site.ErrorPages)
	}
	if fs.errorPageSets != 1 || len(fs.sites["shop"].ErrorPages) != 2 {
		t.Errorf("provider counters = %d, stored = %+v", fs.errorPageSets, fs.sites["shop"].ErrorPages)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/error-pages" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/error-pages") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "/404.html") || !strings.Contains(e.Params, "/50x.html") {
			t.Errorf("audit lost error page rules: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("error page change missing from the audit trail")
	}
}

func TestSiteErrorPagesClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/error-pages",
		`{"rules":[{"code":404,"path":"/404.html"}]}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set error pages = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/error-pages", `{"rules":[]}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear error pages = %d %s", r.StatusCode, body)
	}
	if len(fs.sites["shop"].ErrorPages) != 0 {
		t.Errorf("error pages not cleared: %+v", fs.sites["shop"].ErrorPages)
	}
	if fs.errorPageSets != 2 {
		t.Errorf("provider saw %d writes, want 2", fs.errorPageSets)
	}
}

func TestSiteErrorPagesMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：第 1 条状态码 200 不在支持列表", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_error_pages"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.errorPageErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/error-pages",
			`{"rules":[{"code":404,"path":"/404.html"}]}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteErrorPagesGateAndCSRF(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/error-pages",
		`{"rules":[{"code":404,"path":"/404.html"}]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("error-pages with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.errorPageSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	// Site capability available but the provider lacks the error page
	// interface: 403 capability with the backend reason, never a dead write.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.do(http.MethodPut, "/api/v1/sites/shop/error-pages",
		`{"rules":[{"code":404,"path":"/404.html"}]}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "自定义错误页") {
		t.Errorf("no error page interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.errorPageSets != 0 {
		t.Error("provider called without the error page interface")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/error-pages", `{"rules":[]}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("error-pages without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.errorPageSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteErrorPagesBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/error-pages", `{"rules":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.errorPageSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
