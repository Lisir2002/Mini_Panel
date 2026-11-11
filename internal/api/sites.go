package api

import (
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lisir2002/Mini_Panel/internal/platform"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

// Site management is the third slice of M2: static sites first, then the PHP
// binding in the sixth slice and basic-settings editing (domains, root, index)
// in the seventh. Certificate controls live in site_tls.go; the capability
// bitmap says exactly which half exists (`php` stays degraded,
// `php_version_switch` is the site-level switch, `ssl` covers all three
// certificate sources). The page renders from those states, so a site created
// here cannot pretend to have a half-delivered feature attached to it.
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

// siteSettingsManager is the optional basic-settings editor (domains, root,
// default documents). Missing interface means the page hides the edit button
// instead of offering a form behind an unimplemented method.
func (s *Server) siteSettingsManager() (platform.SiteSettingsManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	sm, ok := m.(platform.SiteSettingsManager)
	if !ok || sm == nil {
		return nil, "该平台的站点 Provider 没有实现站点设置编辑"
	}
	return sm, ""
}

// siteRewriteManager is the optional rewrite-template interface. The template
// list comes from the provider rather than a front-end constant, so the
// selector can only offer ids the server will accept.
func (s *Server) siteRewriteManager() (platform.SiteRewriteManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	rm, ok := m.(platform.SiteRewriteManager)
	if !ok || rm == nil {
		return nil, "该平台的站点 Provider 没有实现伪静态模板"
	}
	return rm, ""
}

// siteProxyManager is the optional reverse-proxy interface. A provider without
// it returns 403 capability with the reason below instead of pretending the
// write endpoint exists.
func (s *Server) siteProxyManager() (platform.SiteProxyManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	pm, ok := m.(platform.SiteProxyManager)
	if !ok || pm == nil {
		return nil, "该平台的站点 Provider 没有实现反向代理"
	}
	return pm, ""
}

// siteRedirectManager is the optional site-wide redirect interface. A provider
// without it returns 403 capability with the reason below.
func (s *Server) siteRedirectManager() (platform.SiteRedirectManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	rm, ok := m.(platform.SiteRedirectManager)
	if !ok || rm == nil {
		return nil, "该平台的站点 Provider 没有实现整站跳转"
	}
	return rm, ""
}

// siteRedirectPathManager is the optional exact-path redirect table. Providers
// that only implement the site-wide redirect endpoint return 403 capability
// rather than pretending path exceptions are available.
func (s *Server) siteRedirectPathManager() (platform.SiteRedirectPathManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	rm, ok := m.(platform.SiteRedirectPathManager)
	if !ok || rm == nil {
		return nil, "该平台的站点 Provider 没有实现按路径跳转"
	}
	return rm, ""
}

// siteHotlinkManager is the optional hotlink-protection interface. A provider
// without it returns 403 capability with the reason below.
func (s *Server) siteHotlinkManager() (platform.SiteHotlinkManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	hm, ok := m.(platform.SiteHotlinkManager)
	if !ok || hm == nil {
		return nil, "该平台的站点 Provider 没有实现防盗链"
	}
	return hm, ""
}

// siteAuthManager is the optional HTTP Basic Auth interface. Clearing is part
// of the same endpoint, so a host without this interface cannot offer the
// password dialog at all.
func (s *Server) siteAuthManager() (platform.SiteAuthManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	am, ok := m.(platform.SiteAuthManager)
	if !ok || am == nil {
		return nil, "该平台的站点 Provider 没有实现访问密码"
	}
	return am, ""
}

// siteRealIPManager is the optional trusted-proxy interface. A provider without
// it cannot offer real-IP resolution; the handler reports the same capability
// reason as the other site write features.
func (s *Server) siteRealIPManager() (platform.SiteRealIPManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	rm, ok := m.(platform.SiteRealIPManager)
	if !ok || rm == nil {
		return nil, "该平台的站点 Provider 没有实现真实 IP 解析"
	}
	return rm, ""
}

// siteTrafficLimitManager is the optional traffic-limit interface. A provider
// without it cannot place nginx's http-level zone definitions at all, so the
// endpoint answers 403 capability with that reason rather than half-writing a
// config the running server would refuse.
func (s *Server) siteTrafficLimitManager() (platform.SiteTrafficLimitManager, string) {
	m, why := s.siteManager()
	if m == nil {
		return nil, why
	}
	lm, ok := m.(platform.SiteTrafficLimitManager)
	if !ok || lm == nil {
		return nil, "该平台的站点 Provider 没有实现流量限制"
	}
	return lm, ""
}

// normalizeSiteMeta validates the panel-side group label and free-text note.
// Neither reaches nginx — this only guards what goes into the store, so the
// bounds are about keeping the UI list sane, not about config injection. A
// group is a single short line; a note may wrap but is capped and stripped of
// control characters. Empty on both sides means "clear the annotation".
func normalizeSiteMeta(group, note string) (string, string, error) {
	group = strings.TrimSpace(group)
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(group) > 64 {
		return "", "", errors.New("分组名称最长 64 个字符")
	}
	for _, r := range group {
		if unicode.IsControl(r) {
			return "", "", errors.New("分组名称不能包含换行或控制字符")
		}
	}
	if utf8.RuneCountInString(note) > 500 {
		return "", "", errors.New("备注最长 500 个字符")
	}
	for _, r := range note {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return "", "", errors.New("备注不能包含控制字符")
		}
	}
	return group, note, nil
}

// mergeSiteMeta joins the stored annotations onto the provider's site rows by
// name. A provider site with no annotation row keeps its empty group/note; an
// annotation for a site the provider no longer reports is simply never joined
// (and handleSiteDelete clears it on the happy path).
func mergeSiteMeta(items []platform.SiteInfo, meta map[string]store.SiteMeta) {
	for i := range items {
		if m, ok := meta[items[i].Name]; ok {
			items[i].Group = m.Group
			items[i].Note = m.Note
		}
	}
}

// handleSitesList is GET /api/v1/sites. Only files the panel wrote itself are
// listed; a hand-written vhost in the same directory is somebody else's
// configuration and is not reported as a panel site. The panel-side group and
// note annotations are joined from the store here, so a site the operator filed
// under a group shows that group even though nothing about it lives in nginx.
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
	meta, err := s.Store.ListSiteMeta()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取站点分组备注失败")
		return
	}
	mergeSiteMeta(items, meta)
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
		Index      []string `json:"index"`
		Rewrite    string   `json:"rewrite"`
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
		Name: body.Name, Domains: body.Domains, Root: body.Root, Index: body.Index,
		Rewrite: body.Rewrite, PHPVersion: phpVersion,
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

// handleSiteUpdate is PUT /api/v1/sites/{name}. The body is a full replacement
// of the editable basics: {domains, root?, index?}. An omitted/empty root keeps
// the current directory; an empty index restores the built-in default list.
// The provider validates hostnames, root confinement and index tokens, and
// re-checks the existing certificate when domains change, so an HTTPS site
// cannot start serving a certificate for names it no longer claims.
func (s *Server) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteSettingsManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Domains []string `json:"domains"`
		Root    string   `json:"root"`
		Index   []string `json:"index"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetBasics(chiParam(r, "name"), body.Domains, body.Root, body.Index)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, site)
	case errors.Is(err, platform.ErrSiteMissing):
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, platform.ErrSiteTLSInvalid):
		writeErr(w, http.StatusUnprocessableEntity, "invalid_tls", err.Error())
	case errors.Is(err, platform.ErrSiteInvalid):
		writeErr(w, http.StatusBadRequest, "invalid_site", err.Error())
	case errors.Is(err, platform.ErrSiteRefused):
		writeErr(w, http.StatusUnprocessableEntity, "nginx_rejected", err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "site_write", "更新站点失败："+err.Error())
	}
}

// handleSiteRewritePresets is GET /api/v1/sites/rewrite-presets. The list is
// bundled in the binary, not downloaded: the design explicitly rejects an
// online template library, and the provider is the single source for both the
// selector and the validator.
func (s *Server) handleSiteRewritePresets(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteRewriteManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	items := m.RewritePresets()
	if items == nil {
		items = []platform.RewritePreset{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleSiteRewrite is PUT /api/v1/sites/{name}/rewrite. The body is
// {"preset":"wordpress"}; "none" removes the template. The provider validates
// the id against its bundled set and refuses a PHP-dependent template on a
// static site, then rewrites the vhost through test-before-reload. A failed
// write leaves the previous template serving.
func (s *Server) handleSiteRewrite(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteRewriteManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Preset string `json:"preset"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetRewrite(chiParam(r, "name"), body.Preset)
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
		writeErr(w, http.StatusInternalServerError, "site_rewrite", "更新伪静态失败："+err.Error())
	}
}

// handleSiteProxy is PUT /api/v1/sites/{name}/proxy. The body is
// {"target":"http://127.0.0.1:3000","websocket":false}; an empty target clears
// the proxy and returns the site to its local static/PHP vhost. The provider
// validates the URL and refuses to overwrite a rewrite template's location /,
// then writes through test-before-reload.
func (s *Server) handleSiteProxy(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteProxyManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Target    string `json:"target"`
		WebSocket bool   `json:"websocket"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetProxy(chiParam(r, "name"), body.Target, body.WebSocket)
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
		writeErr(w, http.StatusInternalServerError, "site_proxy", "更新反向代理失败："+err.Error())
	}
}

// handleSiteRedirect is PUT /api/v1/sites/{name}/redirect. The body is
// {"target":"https://new.example.com","code":301,"keep_path":true}; an empty
// target clears the redirect. The provider validates the URL and refuses to
// overwrite a rewrite template or proxy location /, then writes through
// test-before-reload.
func (s *Server) handleSiteRedirect(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteRedirectManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Target   string `json:"target"`
		Code     int    `json:"code"`
		KeepPath bool   `json:"keep_path"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetRedirect(chiParam(r, "name"), body.Target, body.Code, body.KeepPath)
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
		writeErr(w, http.StatusInternalServerError, "site_redirect", "更新整站跳转失败："+err.Error())
	}
}

// handleSiteRedirectPaths is PUT /api/v1/sites/{name}/redirect-paths. The body
// is {"rules":[{"path":"/old","target":"https://new.example.com","code":301}]};
// an empty rules list clears the table. Paths and targets are validated and
// normalized by the provider, which renders only fixed `location =` blocks.
func (s *Server) handleSiteRedirectPaths(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteRedirectPathManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Rules []platform.SiteRedirectRule `json:"rules"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetRedirectPaths(chiParam(r, "name"), body.Rules)
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
		writeErr(w, http.StatusInternalServerError, "site_redirect_paths", "更新按路径跳转失败："+err.Error())
	}
}

// handleSiteLimits is PUT /api/v1/sites/{name}/traffic-limit. The body is
// {"request_rate":"10r/s","burst":20,"connections":5,"status":429}; an empty
// object (or all fields at their zero values) clears the site's limits. The
// provider validates the rate shape and the numeric bounds, derives the zone
// names from the site name, and writes the http-level zone table alongside the
// vhost in one test-before-reload transaction.
func (s *Server) handleSiteLimits(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteTrafficLimitManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var limit platform.SiteTrafficLimit
	if err := decodeBody(r, &limit); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetLimits(chiParam(r, "name"), limit)
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
		writeErr(w, http.StatusInternalServerError, "site_traffic_limit", "更新流量限制失败："+err.Error())
	}
}

// handleSiteHotlink is PUT /api/v1/sites/{name}/hotlink. The body is
// {"enabled":true,"allow_empty":true}; enabled=false disables the fixed Referer
// check. The provider refuses to enable it while a proxy or redirect owns the
// site, then writes through test-before-reload.
func (s *Server) handleSiteHotlink(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteHotlinkManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Enabled    bool `json:"enabled"`
		AllowEmpty bool `json:"allow_empty"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetHotlink(chiParam(r, "name"), body.Enabled, body.AllowEmpty)
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
		writeErr(w, http.StatusInternalServerError, "site_hotlink", "更新防盗链失败："+err.Error())
	}
}

// handleSiteAuth is PUT /api/v1/sites/{name}/auth. The body is
// {"username":"guest","password":"..."}; an empty username and password clears
// the gate. The provider hashes the password into its own 0600 file and writes
// the fixed auth_basic directives through test-before-reload; the password is
// never echoed back and never appears in the response.
func (s *Server) handleSiteAuth(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteAuthManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetAuth(chiParam(r, "name"), body.Username, body.Password)
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
		writeErr(w, http.StatusInternalServerError, "site_auth", "更新访问密码失败："+err.Error())
	}
}

// handleSiteRealIP is PUT /api/v1/sites/{name}/realip. The body is
// {"from":["10.0.0.0/8"],"header":"X-Forwarded-For"}; an empty list and header
// clears the trusted-proxy block. The provider validates every address/CIDR and
// refuses trust-everything, then renders the fixed set_real_ip_from block.
func (s *Server) handleSiteRealIP(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteRealIPManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		From   []string `json:"from"`
		Header string   `json:"header"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	site, err := m.SetRealIP(chiParam(r, "name"), body.From, body.Header)
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
		writeErr(w, http.StatusInternalServerError, "site_real_ip", "更新真实 IP 解析失败："+err.Error())
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
	name := chiParam(r, "name")
	site, err := m.Delete(name)
	switch {
	case err == nil:
		// Drop the site's panel-side annotation with it. This is best-effort:
		// the deletion already succeeded and a leftover row would show nothing
		// anyway (the list joins against live provider sites), but we clear it
		// so the table stays honest about what is actually annotated.
		if derr := s.Store.DeleteSiteMeta(name); derr != nil && s.Log != nil {
			s.Log.Warn("clear site annotation after delete", "site", name, "error", derr)
		}
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

// handleSiteMeta is PUT /api/v1/sites/{name}/meta. The body is
// {"group":"电商","note":"双 11 后要扩容"}; empty group and empty note clear the
// annotation. This is the one site control that is pure panel data: it never
// touches a vhost or `nginx -t`, because a label and a note are not nginx
// configuration. The site must still be one the provider reports, so the
// annotation cannot be attached to a name the panel does not manage — the
// handler checks that against the provider's list before writing.
func (s *Server) handleSiteMeta(w http.ResponseWriter, r *http.Request) {
	m, why := s.siteManager()
	if m == nil {
		writeErr(w, http.StatusForbidden, "capability", why)
		return
	}
	var body struct {
		Group string `json:"group"`
		Note  string `json:"note"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	name := chiParam(r, "name")
	group, note, err := normalizeSiteMeta(body.Group, body.Note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_site", err.Error())
		return
	}
	// Confirm the provider actually manages this site before storing an
	// annotation keyed by its name; otherwise a mistyped name would quietly
	// accumulate a row nothing ever lists.
	items, err := m.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取站点列表失败")
		return
	}
	var target *platform.SiteInfo
	for i := range items {
		if items[i].Name == name {
			target = &items[i]
			break
		}
	}
	if target == nil {
		writeErr(w, http.StatusNotFound, "not_found", platform.ErrSiteMissing.Error())
		return
	}
	if err := s.Store.SaveSiteMeta(name, group, note); err != nil {
		writeErr(w, http.StatusInternalServerError, "site_meta", "保存站点分组备注失败："+err.Error())
		return
	}
	target.Group = group
	target.Note = note
	writeJSON(w, http.StatusOK, target)
}
