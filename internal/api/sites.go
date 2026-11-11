package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// Site management is the third slice of M2: static sites first, then the PHP
// binding in the sixth slice. Domains are immutable for now and certificate
// controls live in site_tls.go; the capability bitmap says exactly which half
// exists (`php` stays degraded, `php_version_switch` is the site-level switch,
// `ssl` covers all three certificate sources). The page renders from those
// states, so a site created here cannot pretend to have a half-delivered
// feature attached to it.
//
// Write discipline: the provider writes a config, runs `nginx -t`, and only
// reloads when that passes. Every failure path restores the previous file
// before returning, so this handler never has to compensate for a partial
// write of its own.

// siteManager returns the platform's site writer and, when it is missing, the
// reason to show. The reason comes from the bitmap rather than from a new
// sentence here: "site" and "site_write" are the same capability to the
// operator, and two sources of truth would drift.
func (s *Server) siteManager() (platform.SiteManager, string) {
	if s.Plat == nil || s.Caps == nil {
		return nil, "面板未绑定平台或能力位图，站点功能不可用"
	}
	if !s.Caps.Has(platform.FeatWebSite) {
		return nil, s.Caps.Reason(platform.FeatWebSite)
	}
	sp, ok := s.Plat.(platform.SiteProvider)
	if !ok {
		return nil, "该平台尚未实现站点写入 Provider"
	}
	m, ok := sp.Sites()
	if !ok || m == nil {
		return nil, "站点写入 Provider 在当前主机上不可用"
	}
	return m, ""
}

// sitePHPManager is the optional PHP-binding interface. Clearing a binding
// ("static") is allowed even when the bitmap no longer offers PHP — otherwise a
// host that removed php-fpm after a site was bound would have no way to unbind
// it. Choosing a version does require FeatPHPVersionSwitch to be available.
func (s *Server) sitePHPManager() (platform.SitePHPManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	pm, ok := m.(platform.SitePHPManager)
	if !ok || pm == nil {
		return nil, "该平台的站点 Provider 没有实现 PHP 版本绑定"
	}
	return pm, ""
}

// handleSitesList is GET /api/v1/sites. Only files the panel wrote itself are
// listed; a hand-written vhost in the same directory is somebody else's
// configuration and is not reported as a panel site.
func (s *Server) handleSitesList(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	items, err := m.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取站点列表失败")
		return
	}
	if items == nil {
		items = []platform.SiteInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": len(items), "items": items})
}

// handleSiteCreate is POST /api/v1/sites. Validation happens in the provider,
// which owns the same rules the file format needs; duplicating a second copy
// here would let the two disagree about what a legal site is.
func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Name       string   `json:"name"`
		Domains    []string `json:"domains"`
		Root       string   `json:"root"`
		PHPVersion string   `json:"php_version"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	phpVersion := strings.TrimSpace(body.PHPVersion)
	if phpVersion != "" {
		if s.Caps == nil || !s.Caps.Has(platform.FeatPHPVersionSwitch) {
			why := "PHP 版本绑定在当前主机上不可用"
			if s.Caps != nil {
				why = s.Caps.Reason(platform.FeatPHPVersionSwitch)
			}
			writeErr(w, http.StatusForbidden, "capability", why)
			return
		}
		if _, ok := m.(platform.SitePHPManager); !ok {
			writeErr(w, http.StatusForbidden, "capability", "该平台的站点 Provider 没有实现 PHP 版本绑定")
			return
		}
	}
	site, err := m.Create(platform.SiteSpec{
		Name: body.Name, Domains: body.Domains, Root: body.Root,
		PHPVersion: phpVersion,
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, site)
	case errors.Is(err, platform.ErrSiteInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_site", err.Error())
	case errors.Is(err, platform.ErrSiteExists):
		writeErr(w, http.StatusConflict, "site_exists", err.Error())
	case errors.Is(err, platform.ErrSitePHP):
		writeErr(w, http.StatusUnprocessableEntity, "php_unavailable", err.Error())
	case errors.Is(err, platform.ErrSiteRefused):
		// The config did not survive `nginx -t`, or the reload was refused. The
		// write has already been rolled back; this is a 422 because the request
		// was well-formed and the panel understood it, but nginx would not take it.
		writeErr(w, http.StatusUnprocessableEntity, "nginx_rejected", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "site_write", "创建站点失败："+err.Error())
	}
}

// handleSitePHP is PUT /api/v1/sites/{name}/php. The body is
// {"php_version":"8.3"}; an empty string switches the site back to static.
// The provider resolves the version to a socket against live discovery, then
// rewrites the vhost through test-before-reload, so a failed switch leaves the
// previous binding serving.
func (s *Server) handleSitePHP(w http.ResponseWriter, r *http.Request) {
	m, why := s.sitePHPManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		PHPVersion string `json:"php_version"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	version := strings.TrimSpace(body.PHPVersion)
	if version != "" {
		if s.Caps == nil || !s.Caps.Has(platform.FeatPHPVersionSwitch) {
			why := "PHP 版本绑定在当前主机上不可用"
			if s.Caps != nil {
				why = s.Caps.Reason(platform.FeatPHPVersionSwitch)
			}
			writeErr(w, http.StatusForbidden, "capability", why)
			return
		}
	}
	site, err := m.SetPHP(chiParam(r, "name"), version)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, site)
	case errors.Is(err, platform.ErrSiteMissing):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, platform.ErrSitePHP):
		writeErr(w, http.StatusUnprocessableEntity, "php_unavailable", err.Error())
	case errors.Is(err, platform.ErrSiteInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_site", err.Error())
	case errors.Is(err, platform.ErrSiteRefused):
		writeErr(w, http.StatusUnprocessableEntity, "nginx_rejected", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "site_php", "切换站点 PHP 版本失败："+err.Error())
	}
}

// handleSiteDelete is DELETE /api/v1/sites/{name}. The document root is
// deliberately left on disk: deleting a vhost is a configuration action, and
// turning it into a recursive delete of /www/wwwroot/<name> is a data-loss
// button one mistyped name away.
func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	site, err := m.Delete(chiParam(r, "name"))
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, site)
	case errors.Is(err, platform.ErrSiteMissing):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, platform.ErrSiteInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_site", err.Error())
	case errors.Is(err, platform.ErrSiteRefused):
		writeErr(w, http.StatusUnprocessableEntity, "nginx_rejected", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "site_write", "删除站点失败："+err.Error())
	}
}
