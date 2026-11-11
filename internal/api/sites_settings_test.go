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

// The edit endpoint is the first site write whose body is a replacement of
// operator data (domains/root/index) rather than a toggle. These tests pin the
// HTTP contract: the route pattern is audited, errors keep their identity
// (invalid vs certificate-vs-config rejection), and CSRF applies like every
// other write.

func TestSiteCreateWithCustomIndex(t *testing.T) {
	p, fs := newSitePanel(t, true)
	r, body := p.do(http.MethodPost, "/api/v1/sites",
		`{"name":"blog","domains":["blog.example.com"],"index":["home.html","index.html"]}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("create json: %v\n%s", err, body)
	}
	if strings.Join(site.Index, ",") != "home.html,index.html" {
		t.Errorf("index = %v", site.Index)
	}
	if strings.Join(fs.sites["blog"].Index, ",") != "home.html,index.html" {
		t.Errorf("provider did not see the index list")
	}
}

func TestSiteUpdateChangesBasics(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPut, "/api/v1/sites/blog",
		`{"domains":["new.example.com","www.new.example.com"],"root":"/www/wwwroot/data","index":["home.html"]}`,
		p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("update = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("update json: %v\n%s", err, body)
	}
	if len(site.Domains) != 2 || site.Domains[0] != "new.example.com" || site.Root != "/www/wwwroot/data" {
		t.Errorf("updated row = %+v", site)
	}
	if len(site.Index) != 1 || site.Index[0] != "home.html" {
		t.Errorf("updated index = %v", site.Index)
	}
	if fs.settingsSets != 1 {
		t.Errorf("provider saw %d edits, want 1", fs.settingsSets)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "PUT /api/v1/sites/{name}" {
			found = true
			if !strings.Contains(e.Target, "/api/v1/sites/blog") {
				t.Errorf("audit target = %q", e.Target)
			}
		}
	}
	if !found {
		t.Errorf("site edit missing from the audit trail")
	}
}

func TestSiteUpdateMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：域名重复", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：证书不覆盖新域名", platform.ErrSiteTLSInvalid), http.StatusUnprocessableEntity, "invalid_tls"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
	}
	for _, tc := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "blog")
		fs.settingsErr = tc.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/blog",
			`{"domains":["new.example.com"]}`, p.csrfHeader())
		if r.StatusCode != tc.code {
			t.Errorf("err %v = %d %s, want %d", tc.err, r.StatusCode, body, tc.code)
		}
		if !strings.Contains(body, `"kind":"`+tc.kind+`"`) {
			t.Errorf("err %v kind missing from %s", tc.err, body)
		}
	}
}

func TestSiteUpdateGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	if r, body := p.do(http.MethodPut, "/api/v1/sites/blog",
		`{"domains":["new.example.com"]}`, p.csrfHeader()); r.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("edit while site unavailable = %d %s", r.StatusCode, body)
	}
	if fs.settingsSets != 0 {
		t.Error("provider was called while the capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, _ := p.do(http.MethodPut, "/api/v1/sites/blog",
		`{"domains":["new.example.com"]}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("edit without csrf = %d, want 403", r.StatusCode)
	}
	if fs.settingsSets != 0 {
		t.Error("provider was called without CSRF")
	}
}
