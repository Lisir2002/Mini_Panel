package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// Site HTTPS is the fourth slice of M2: an operator can generate a self-signed
// certificate or upload a chain+key, and nginx is only reloaded after the same
// test-before-take-effect protocol as site creation. ACME is still not here, so
// the bitmap reports ssl as degraded and this handler refuses only when the
// state is unavailable or foreign. A handler that gated on Has() would hide the
// half that does work; a handler that ignored the bitmap would advertise the
// half that does not.

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
	default:
		writeErr(w, http.StatusInternalServerError, "site_tls", "站点证书操作失败："+err.Error())
	}
}
