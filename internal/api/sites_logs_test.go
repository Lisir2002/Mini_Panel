package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// 第十八片 adds one read-only endpoint: GET /sites/{name}/logs. The HTTP layer
// is thin (gate, parse kind/lines, map the provider result or error), so these
// tests pin exactly that: defaults and params, the honest exists=false answer,
// bad params, error mapping, and capability gating. The tail/window/ownership
// behaviour itself is pinned in internal/nginx.

func TestSiteLogsReadDefaultsAndParams(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.get("/api/v1/sites/shop/logs")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("logs = %d %s", r.StatusCode, body)
	}
	var lg platform.SiteLogInfo
	if err := json.Unmarshal([]byte(body), &lg); err != nil {
		t.Fatalf("logs json: %v\n%s", err, body)
	}
	if fs.lastLogKind != "access" || fs.lastLogLines != 100 {
		t.Errorf("defaults = kind %q lines %d, want access/100", fs.lastLogKind, fs.lastLogLines)
	}
	if !lg.Exists || lg.Kind != "access" || len(lg.Lines) == 0 || lg.Path == "" || lg.Size == 0 {
		t.Errorf("log answer = %+v", lg)
	}

	if r, body := p.get("/api/v1/sites/shop/logs?kind=error&lines=5"); r.StatusCode != http.StatusOK {
		t.Fatalf("error logs = %d %s", r.StatusCode, body)
	}
	if fs.lastLogKind != "error" || fs.lastLogLines != 5 {
		t.Errorf("params = kind %q lines %d, want error/5", fs.lastLogKind, fs.lastLogLines)
	}
	if fs.logReads != 2 {
		t.Errorf("provider reads = %d, want 2", fs.logReads)
	}
}

func TestSiteLogsMissingFileIsHonest(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	fs.logMissing = true
	r, body := p.get("/api/v1/sites/shop/logs")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("missing-file logs = %d %s", r.StatusCode, body)
	}
	var lg platform.SiteLogInfo
	if err := json.Unmarshal([]byte(body), &lg); err != nil {
		t.Fatal(err)
	}
	if lg.Exists || len(lg.Lines) != 0 {
		t.Errorf("missing file must answer exists=false with no lines, got %+v", lg)
	}
}

func TestSiteLogsBadParams(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	for _, q := range []string{"lines=abc", "lines=0", "lines=501", "kind=secret"} {
		r, body := p.get("/api/v1/sites/shop/logs?" + q)
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"invalid_site"`) {
			t.Errorf("%s = %d %s, want 400 invalid_site", q, r.StatusCode, body)
		}
	}
	if fs.logReads != 0 {
		t.Errorf("provider read %d times on rejected params", fs.logReads)
	}
}

func TestSiteLogsMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：日志类型只能是 access 或 error", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_logs"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.logsErr = c.err
		r, body := p.get("/api/v1/sites/shop/logs")
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
	// Unknown site without a provider error still maps to 404.
	p, _ := newSitePanel(t, true)
	if r, body := p.get("/api/v1/sites/ghost/logs"); r.StatusCode != http.StatusNotFound || !strings.Contains(body, `"kind":"not_found"`) {
		t.Errorf("ghost site = %d %s, want 404 not_found", r.StatusCode, body)
	}
}

// noLogSitePlatform offers a site provider that implements only the base
// SiteManager — every optional interface is stripped. That is what a platform
// without the log seam looks like, and the endpoint must refuse with a reason.
type noLogSitePlatform struct{ fakeSitePlatform }

func (f noLogSitePlatform) Sites() (platform.SiteManager, bool) {
	m, ok := f.fakeSitePlatform.Sites()
	if !ok {
		return nil, false
	}
	return struct{ platform.SiteManager }{m}, true
}

func TestSiteLogsGate(t *testing.T) {
	// Site capability unavailable at all.
	p, fs := newSitePanel(t, false)
	r, body := p.get("/api/v1/sites/shop/logs")
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.logReads != 0 {
		t.Errorf("provider read while site capability unavailable")
	}

	// Site capability available but the provider lacks the log interface.
	fs = newFakeSites()
	p = newPanelWith(t, nil, noLogSitePlatform{fakeSitePlatform{t: t, site: fs, ready: true}}, siteCaps(true, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body = p.get("/api/v1/sites/shop/logs")
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) || !strings.Contains(body, "站点日志查看") {
		t.Errorf("no log interface = %d %s, want 403 capability with reason", r.StatusCode, body)
	}
	if fs.logReads != 0 {
		t.Errorf("provider read without the log interface")
	}
}
