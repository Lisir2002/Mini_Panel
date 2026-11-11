package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// Group and note are the one site control that never touches nginx: they live
// in the store's site_meta table and are joined onto the list by name. These
// tests pin that round-trip — set, clear, the list join, the "site must exist"
// precondition, validation, capability gating, CSRF, malformed bodies, and the
// cleanup that runs when a site is deleted.

func TestSiteMetaSetAndJoinList(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta",
		`{"group":"电商","note":"双 11 后要扩容"}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("meta = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("meta json: %v\n%s", err, body)
	}
	if site.Group != "电商" || site.Note != "双 11 后要扩容" {
		t.Fatalf("response meta = %q / %q", site.Group, site.Note)
	}

	// The list endpoint must join the annotation back onto the row, even though
	// the provider itself knows nothing about it.
	r, body = p.get("/api/v1/sites")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("list = %d %s", r.StatusCode, body)
	}
	var resp struct {
		Items []platform.SiteInfo `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("list json: %v\n%s", err, body)
	}
	if len(resp.Items) != 1 || resp.Items[0].Group != "电商" || resp.Items[0].Note != "双 11 后要扩容" {
		t.Fatalf("list did not join meta: %+v", resp.Items)
	}

	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "PUT /api/v1/sites/{name}/meta" {
			continue
		}
		found = true
		if !strings.Contains(e.Target, "/api/v1/sites/shop/meta") {
			t.Errorf("audit target = %q", e.Target)
		}
		if !strings.Contains(e.Params, "电商") {
			t.Errorf("audit lost the group value: %q", e.Params)
		}
	}
	if !found {
		t.Errorf("meta change missing from the audit trail")
	}
}

func TestSiteMetaClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta",
		`{"group":"电商"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set = %d %s", r.StatusCode, body)
	}
	// An empty body is the documented clear path: both fields blank deletes the row.
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta", `{}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("clear json: %v", err)
	}
	if site.Group != "" || site.Note != "" {
		t.Errorf("cleared response still carries meta: %q / %q", site.Group, site.Note)
	}
	meta, err := p.st.ListSiteMeta()
	if err != nil {
		t.Fatalf("read store meta: %v", err)
	}
	if _, ok := meta["shop"]; ok {
		t.Errorf("clear left a store row: %+v", meta["shop"])
	}
}

func TestSiteMetaRejectsUnknownSite(t *testing.T) {
	p, _ := newSitePanel(t, true)
	r, body := p.do(http.MethodPut, "/api/v1/sites/ghost/meta",
		`{"group":"电商"}`, p.csrfHeader())
	if r.StatusCode != http.StatusNotFound || !strings.Contains(body, `"kind":"not_found"`) {
		t.Errorf("meta for unmanaged site = %d %s, want 404 not_found", r.StatusCode, body)
	}
	meta, _ := p.st.ListSiteMeta()
	if _, ok := meta["ghost"]; ok {
		t.Errorf("annotation was stored for a site the provider does not manage")
	}
}

func TestSiteMetaValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"group too long", `{"group":"` + strings.Repeat("a", 65) + `"}`},
		{"group newline", `{"group":"a\nb"}`},
		{"note too long", `{"note":"` + strings.Repeat("x", 501) + `"}`},
		{"note control char", "{\"note\":\"a\\u0000b\"}"},
	}
	for _, c := range cases {
		// Validation runs before the provider existence check, so a real seeded
		// site is not needed to reach the 400.
		p, _ := newSitePanel(t, true)
		r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta", c.body, p.csrfHeader())
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"invalid_site"`) {
			t.Errorf("%s = %d %s, want 400 invalid_site", c.name, r.StatusCode, body)
		}
	}
}

func TestSiteMetaGateAndCSRF(t *testing.T) {
	p, fs := newSitePanel(t, false)
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta",
		`{"group":"电商"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Errorf("meta with site unavailable = %d %s, want 403 capability", r.StatusCode, body)
	}

	p, fs = newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, _ = p.do(http.MethodPut, "/api/v1/sites/shop/meta", `{"group":"电商"}`, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("meta without CSRF = %d, want 403", r.StatusCode)
	}
	meta, _ := p.st.ListSiteMeta()
	if _, ok := meta["shop"]; ok {
		t.Error("annotation stored without CSRF")
	}
}

func TestSiteMetaBadJSON(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta", `{"group":`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"bad_request"`) {
		t.Errorf("bad json = %d %s", r.StatusCode, body)
	}
}

// Deleting a site clears its annotation row, so the site_meta table does not
// accrete rows for names the provider no longer reports.
func TestSiteDeleteClearsMeta(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "shop")
	if r, body := p.do(http.MethodPut, "/api/v1/sites/shop/meta",
		`{"group":"电商","note":"x"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set meta = %d %s", r.StatusCode, body)
	}
	if r, body := p.do(http.MethodDelete, "/api/v1/sites/shop", "", p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d %s", r.StatusCode, body)
	}
	meta, err := p.st.ListSiteMeta()
	if err != nil {
		t.Fatalf("read store meta: %v", err)
	}
	if _, ok := meta["shop"]; ok {
		t.Errorf("delete left an orphan annotation row: %+v", meta)
	}
	if fs.deleted != 1 {
		t.Errorf("provider deletes = %d, want 1", fs.deleted)
	}
}
