package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// Site HTTPS has three sources: manual upload, self-signed, and ACME HTTP-01.
// The manual endpoints in this file stay local and fast; ACME lives on its own
// route because it waits for a CA. All of them install through the same nginx
// provider, so test-before-reload and rollback are not reimplemented per source.
// The handlers accept the bitmap's degraded state as well as available, because
// the manual half is genuinely usable on a provider without ACME.

func (s *Server) siteTLSManager() (platform.SiteTLSManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	if s.Caps == nil {
		return nil, "面板未绑定能力位图，站点证书功能不可用"
	}
	switch s.Caps.State(platform.FeatSSL) {
	case platform.StateAvailable, platform.StateDegraded:
	default:
		return nil, s.Caps.Reason(platform.FeatSSL)
	}
	tm, ok := m.(platform.SiteTLSManager)
	if !ok || tm == nil {
		return nil, "该平台的站点证书 Provider 未实现"
	}
	return tm, ""
}

// handleSiteTLSSet is POST /api/v1/sites/{name}/tls. mode=selfsigned needs no
// PEM; mode=upload requires both halves. The provider owns certificate
// validation (pair match, validity window, domain coverage); this layer only
// rejects a request that is incomplete before it reaches the filesystem.
func (s *Server) handleSiteTLSSet(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteTLSManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Mode     string `json:"mode"`
		CertPEM  string `json:"cert_pem"`
		KeyPEM   string `json:"key_pem"`
		Redirect bool   `json:"redirect"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	name := chiParam(r, "name")
	var (
		site platform.SiteInfo
		err  error
	)
	switch strings.ToLower(strings.TrimSpace(body.Mode)) {
	case "selfsigned":
		site, err = m.SetSelfSigned(name, body.Redirect)
	case "upload":
		if strings.TrimSpace(body.CertPEM) == "" || strings.TrimSpace(body.KeyPEM) == "" {
			writeErr(w, http.StatusBadRequest, "invalid_tls", "上传模式需要 cert_pem 与 key_pem")
			return
		}
		site, err = m.SetCertificate(name, body.CertPEM, body.KeyPEM, body.Redirect)
	default:
		writeErr(w, http.StatusBadRequest, "invalid_tls", "mode 只能是 selfsigned 或 upload")
		return
	}
	s.writeSiteTLSResult(w, site, err)
}

// siteACMEManager has the same ssl gate as the manual endpoints, plus the ACME
// interface assertion. A provider that only knows how to install uploaded
// certificates must not receive an issuance request; the bitmap stays degraded
// there and this method explains the missing half rather than panicking on a
// nil type assertion.
func (s *Server) siteACMEManager() (platform.SiteACMEManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	if s.Caps == nil {
		return nil, "面板未绑定能力位图，ACME 签发不可用"
	}
	switch s.Caps.State(platform.FeatSSL) {
	case platform.StateAvailable, platform.StateDegraded:
	default:
		return nil, s.Caps.Reason(platform.FeatSSL)
	}
	am, ok := m.(platform.SiteACMEManager)
	if !ok || am == nil {
		return nil, "该平台的站点证书 Provider 没有实现 ACME 自动签发"
	}
	return am, ""
}

// handleSiteACME is POST /api/v1/sites/{name}/acme. It is a separate endpoint
// from the TLS upload because it can spend minutes talking to the CA and
// satisfying challenges; mixing that into the quick local upload call would make
// every client timeout serve both operations badly.
func (s *Server) handleSiteACME(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteACMEManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Redirect bool `json:"redirect"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.ObtainACME(r.Context(), chiParam(r, "name"), body.Redirect)
	s.writeSiteTLSResult(w, site, err)
}

// handleSiteTLSClear is DELETE /api/v1/sites/{name}/tls: back to plain HTTP.
// The certificate files are removed by the provider only after nginx accepted
// the HTTP-only config.
func (s *Server) handleSiteTLSClear(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteTLSManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	site, err := m.ClearCertificate(chiParam(r, "name"))
	s.writeSiteTLSResult(w, site, err)
}

func (s *Server) writeSiteTLSResult(w http.ResponseWriter, site platform.SiteInfo, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, site)
	case errors.Is(err, platform.ErrSiteMissing):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, platform.ErrSiteTLSInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_tls", err.Error())
	case errors.Is(err, platform.ErrSiteInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_site", err.Error())
	case errors.Is(err, platform.ErrSiteRefused):
		writeErr(w, http.StatusUnprocessableEntity, "nginx_rejected", err.Error())
	case errors.Is(err, platform.ErrACMEUnsupported):
		writeErr(w, http.StatusUnprocessableEntity, "acme_unsupported", err.Error())
	case errors.Is(err, platform.ErrACMEFailed):
		// The request was valid and the challenge interval has already been
		// waited out; the failure is a DNS/port/CA fact the operator must see.
		writeErr(w, http.StatusUnprocessableEntity, "acme_failed", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "site_tls", "站点证书操作失败："+err.Error())
	}
}
