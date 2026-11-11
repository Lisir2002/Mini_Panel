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

// Traffic limits write two files inside the provider, but the HTTP contract is
// a single PUT: one body in, one site row back. These tests pin the round-trip,
// the clear semantics, the error mapping, capability gating, CSRF and malformed
// bodies. What the provider does with nginx zones is pinned in internal/nginx.

func TestSiteTrafficLimitUpdateAndAudit(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit",
		`{"request_rate":"10r/s","burst":20,"connections":5,"status":429}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("traffic-limit = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("traffic-limit json: %v\n%s", err, body)
	}
	if site.Limits == nil || site.Limits.RequestRate != "10r/s" || site.Limits.Burst != 20 ||
		site.Limits.Connections != 5 || site.Limits.Status != 429 {
		t.Fatalf("response limits = %+v", site.Limits)
	}
	if fs.limitSets != 1 || fs.sites["shop"].Limits == nil {
		t.Errorf("provider counters = %d, stored = %+v", fs.limitSets, fs.sites["shop"].Limits)
	}
	// The response must not invent zone names: they belong to the provider.
	if strings.Contains(body, "zone") || strings.Contains(body, "mp_shop") {
		t.Errorf("response leaked provider zone names: %s", body)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/traffic-limit" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/traffic-limit") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "10r/s") || !strings.Contains(e.Params, "429") {
			t.Errorf("audit lost the limit values: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("traffic-limit change missing from the audit trail")
	}
}

func TestSiteTrafficLimitClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit",
		`{"connections":30}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set connections = %d %s", r.StatusCode, body)
	}
	if fs.sites["shop"].Limits == nil {
		t.Fatalf("connections limit was not stored")
	}
	// An empty body is the documented clear operation — the rescue path when a
	// limit is throttling the site and the operator cannot remember the values.
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit", `{}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear limits = %d %s", r.StatusCode, body)
	}
	if fs.sites["shop"].Limits != nil {
		t.Errorf("limits not cleared: %+v", fs.sites["shop"].Limits)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("clear json: %v", err)
	}
	if site.Limits != nil {
		t.Errorf("cleared response still carries limits: %+v", site.Limits)
	}
	if fs.limitSets != 2 {
		t.Errorf("provider saw %d writes, want 2", fs.limitSets)
	}
}

func TestSiteTrafficLimitMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：请求速率上限需要是 10r/s、200r/m、100r 这类形状", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		// The "no http-level include on this host" refusal is the provider's
		// answer to an input it cannot place, so it is a 400 with its reason.
		{fmt.Errorf("%w：本机 nginx.conf 里没有通配形式的 http 级 include", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] unknown limit_req zone", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_traffic_limit"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "shop")
		fs.limitErr = c.err
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit",
			`{"request_rate":"10r/s"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteTrafficLimitGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit",
		`{"request_rate":"10r/s"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("traffic-limit with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}
	if fs.limitSets != 0 {
		t.Error("provider called while the site capability was unavailable")
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit", `{}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("traffic-limit without CSRF = %d, want 403", r.StatusCode)
	}
	if fs.limitSets != 0 {
		t.Error("provider called without CSRF")
	}
}

func TestSiteTrafficLimitBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/traffic-limit", `{"request_rate":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
	if fs.limitSets != 0 {
		t.Error("provider called with a malformed body")
	}
}
