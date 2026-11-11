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

// The TLS endpoints sit on top of the same capability gate as the rest of the
// site surface, with one deliberate difference: ssl is *degraded* while ACME is
// missing, yet these handlers must stay reachable because manual upload and
// self-signed certificates do work. These tests pin both halves of that
// contract, plus the certificate-shaped secret handling on the audit trail.

func seedSite(t *testing.T, p *panel, fs *fakeSites, name string) platform.SiteInfo {
	t.Helper()
	r, body := p.do(http.MethodPost, "/api/v1/sites",
		fmt.Sprintf(`{"name":%q,"domains":[%q]}`, name, name+".example.com"), p.csrfHeader())
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("seed site = %d %s", r.StatusCode, body)
	}
	return fs.sites[name]
}

func TestSiteTLSSetSelfSigned(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPost, "/api/v1/sites/blog/tls",
		`{"mode":"selfsigned","redirect":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("set self-signed = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("tls response json: %v\n%s", err, body)
	}
	if site.TLS == nil || !site.TLS.Enabled || !site.TLS.SelfSigned || !site.TLS.Redirect {
		t.Errorf("tls row = %+v", site.TLS)
	}
	if fs.tlsSets != 1 || fs.tlsClears != 0 {
		t.Errorf("provider counters: sets=%d clears=%d", fs.tlsSets, fs.tlsClears)
	}
}

func TestSiteTLSUploadRequiresBothPEMs(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	for _, body := range []string{
		`{"mode":"upload","cert_pem":"-----BEGIN CERTIFICATE-----"}`,
		`{"mode":"upload","key_pem":"-----BEGIN PRIVATE KEY-----"}`,
	} {
		r, resp := p.do(http.MethodPost, "/api/v1/sites/blog/tls", body, p.csrfHeader())
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(resp, `"kind":"invalid_tls"`) {
			t.Errorf("incomplete upload = %d %s", r.StatusCode, resp)
		}
	}
	if fs.tlsSets != 0 {
		t.Errorf("provider was called %d times for incomplete uploads", fs.tlsSets)
	}
}

func TestSiteTLSRejectsUnknownMode(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPost, "/api/v1/sites/blog/tls", `{"mode":"acme"}`, p.csrfHeader())
	if r.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"kind":"invalid_tls"`) {
		t.Errorf("unknown mode = %d %s", r.StatusCode, body)
	}
	if fs.tlsSets != 0 {
		t.Errorf("provider was called for an unknown mode")
	}
}

func TestSiteTLSMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{platform.ErrSiteMissing, http.StatusNotFound, "not_found"},
		{fmt.Errorf("%w：证书与私钥不匹配", platform.ErrSiteTLSInvalid), http.StatusBadRequest, "invalid_tls"},
		{fmt.Errorf("%w：名字不合法", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
		{fmt.Errorf("disk on fire"), http.StatusInternalServerError, "site_tls"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "blog")
		fs.tlsErr = c.err
		r, body := p.do(http.MethodPost, "/api/v1/sites/blog/tls",
			`{"mode":"selfsigned"}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

// The bitmap says ssl is degraded, and that must not block the two modes that
// are implemented. When it is unavailable for another reason, the refusal has
// to quote the bitmap rather than invent a new sentence.
func TestSiteTLSGate(t *testing.T) {
	fs := newFakeSites()
	caps := siteCaps(true, "")
	reason := "本机没有可写的证书目录"
	caps.Features[platform.FeatSSL] = platform.Feature{
		State: platform.StateUnavailable, Reason: reason,
	}
	p := newPanelWith(t, nil, fakeSitePlatform{t: t, site: fs, ready: true}, caps)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPost, "/api/v1/sites/blog/tls",
		`{"mode":"selfsigned"}`, p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, `"kind":"capability"`) {
		t.Fatalf("ssl unavailable = %d %s", r.StatusCode, body)
	}
	if !strings.Contains(body, reason) {
		t.Errorf("refusal does not quote the bitmap: %s", body)
	}
	if fs.tlsSets != 0 {
		t.Errorf("provider was called while ssl was unavailable")
	}
}

func TestSiteTLSWritesRequireCSRF(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, _ := p.do(http.MethodPost, "/api/v1/sites/blog/tls",
		`{"mode":"selfsigned"}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("set without csrf = %d, want 403", r.StatusCode)
	}
	if r, _ := p.do(http.MethodDelete, "/api/v1/sites/blog/tls", "", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("clear without csrf = %d, want 403", r.StatusCode)
	}
	if fs.tlsSets != 0 || fs.tlsClears != 0 {
		t.Errorf("provider was called without CSRF (sets=%d clears=%d)", fs.tlsSets, fs.tlsClears)
	}
}

func TestSiteTLSClear(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, body := p.do(http.MethodPost, "/api/v1/sites/blog/tls",
		`{"mode":"selfsigned","redirect":true}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("set = %d %s", r.StatusCode, body)
	}
	r, body := p.do(http.MethodDelete, "/api/v1/sites/blog/tls", "", p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("clear = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("clear json: %v\n%s", err, body)
	}
	if site.TLS != nil {
		t.Errorf("tls still present after clear: %+v", site.TLS)
	}
	if fs.tlsClears != 1 {
		t.Errorf("clear count = %d, want 1", fs.tlsClears)
	}
}

// TestSiteTLSUploadIsAuditedWithoutLeakingPEMs does three things at once:
// the write joins the audit trail under its route pattern; cert_pem/key_pem are
// masked; and a body larger than the audit middleware's old 8 KiB capture limit
// still reaches the provider intact (the truncation bug this slice fixed).
func TestSiteTLSUploadIsAuditedWithoutLeakingPEMs(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	marker := "MUST-NOT-LEAK-IN-AUDIT"
	certPEM := "-----BEGIN CERTIFICATE-----\n" + marker + "\n" +
		strings.Repeat("QUJDRA==\n", 2000) + "-----END CERTIFICATE-----\n"
	keyPEM := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("QUJDRA==\n", 500) +
		"-----END PRIVATE KEY-----\n"
	body, err := json.Marshal(map[string]any{
		"mode": "upload", "cert_pem": certPEM, "key_pem": keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 8<<10 {
		t.Fatalf("test body is %d bytes, needs to exceed the old 8 KiB capture", len(body))
	}
	r, resp := p.do(http.MethodPost, "/api/v1/sites/blog/tls", string(body), p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d %s", r.StatusCode, resp)
	}
	if fs.lastCertLen != len(certPEM) {
		t.Errorf("provider saw %d certificate bytes, want %d (body truncated?)", fs.lastCertLen, len(certPEM))
	}
	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action != "POST /api/v1/sites/{name}/tls" {
			continue
		}
		found = true
		if strings.Contains(e.Params, marker) {
			t.Errorf("audit params leaked the certificate: %s", e.Params)
		}
		if !strings.Contains(e.Params, "cert_pem=***") || !strings.Contains(e.Params, "key_pem=***") {
			t.Errorf("upload params not masked: %s", e.Params)
		}
		if e.Hash == "" {
			t.Error("audit row has no params hash")
		}
	}
	if !found {
		t.Errorf("TLS write missing from the audit trail: %+v", entries)
	}
}

// ACME is a separate endpoint because it talks to a CA. These tests pin the
// HTTP contract: capability gate, provider call, error kinds, and CSRF. The CA
// protocol itself is tested in internal/acme (including a Pebble integration
// run), not by pretending a fake Sites object issued a certificate.
func TestSiteACMEIssuesAndMarksSource(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	r, body := p.do(http.MethodPost, "/api/v1/sites/blog/acme",
		`{"redirect":true}`, p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("acme = %d %s", r.StatusCode, body)
	}
	var site platform.SiteInfo
	if err := json.Unmarshal([]byte(body), &site); err != nil {
		t.Fatalf("acme json: %v\n%s", err, body)
	}
	if site.TLS == nil || !site.TLS.ACME || !site.TLS.Redirect || site.TLS.SelfSigned {
		t.Errorf("acme tls row = %+v", site.TLS)
	}
	if fs.acmeCalls != 1 {
		t.Errorf("acme calls = %d, want 1", fs.acmeCalls)
	}
	entries, _, err := audit.New(p.st).List(50, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "POST /api/v1/sites/{name}/acme" {
			found = true
		}
	}
	if !found {
		t.Error("ACME issuance missing from the audit trail")
	}
}

func TestSiteACMEMapsErrors(t *testing.T) {
	cases := []struct {
		err  error
		kind string
	}{
		{platform.ErrSiteMissing, "not_found"},
		{fmt.Errorf("%w：*.example.com 是通配符", platform.ErrACMEUnsupported), "acme_unsupported"},
		{fmt.Errorf("%w：CA 未通过验证", platform.ErrACMEFailed), "acme_failed"},
		{fmt.Errorf("%w：nginx: bad", platform.ErrSiteRefused), "nginx_rejected"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		seedSite(t, p, fs, "blog")
		fs.acmeErr = c.err
		r, body := p.do(http.MethodPost, "/api/v1/sites/blog/acme", `{}`, p.csrfHeader())
		if r.StatusCode != http.StatusUnprocessableEntity && c.kind != "not_found" {
			t.Errorf("err %v = %d %s, want 422 %s", c.err, r.StatusCode, body, c.kind)
		}
		if c.kind == "not_found" && r.StatusCode != http.StatusNotFound {
			t.Errorf("missing site = %d %s, want 404", r.StatusCode, body)
		}
		if !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v body = %s, want kind %s", c.err, body, c.kind)
		}
	}
}

func TestSiteACMEWritesRequireCSRF(t *testing.T) {
	p, fs := newSitePanel(t, true)
	seedSite(t, p, fs, "blog")
	if r, _ := p.do(http.MethodPost, "/api/v1/sites/blog/acme", `{}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("acme without csrf = %d, want 403", r.StatusCode)
	}
	if fs.acmeCalls != 0 {
		t.Errorf("ACME provider called without CSRF")
	}
}
