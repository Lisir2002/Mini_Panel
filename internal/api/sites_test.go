package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// The site endpoints are the first HTTP surface whose availability depends on
// the host. These tests use a fake SiteProvider so both branches — available
// and unavailable — are exercised on every machine, including the CI box that
// has no nginx. The write discipline itself (test → reload → rollback) is
// pinned in internal/nginx; what is asserted here is the HTTP contract around
// it: capability gate, status codes, CSRF, and the audit trail.

type fakeSites struct {
	sites        map[string]platform.SiteInfo
	createErr    error
	deleteErr    error
	tlsErr       error
	acmeErr      error
	phpErr       error
	settingsErr  error
	rewriteErr   error
	proxyErr     error
	redirectErr  error
	hotlinkErr   error
	authErr      error
	created      int
	deleted      int
	tlsSets      int
	tlsClears    int
	acmeCalls    int
	phpSets      int
	phpClears    int
	settingsSets int
	rewriteSets  int
	proxySets    int
	redirectSets int
	hotlinkSets  int
	authSets     int
	lastCertLen  int
}

func newFakeSites() *fakeSites {
	return &fakeSites{sites: map[string]platform.SiteInfo{}}
}

func (f *fakeSites) List() ([]platform.SiteInfo, error) {
	out := make([]platform.SiteInfo, 0, len(f.sites))
	for _, s := range f.sites {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeSites) Create(spec platform.SiteSpec) (platform.SiteInfo, error) {
	if f.createErr != nil {
		return platform.SiteInfo{}, f.createErr
	}
	if _, ok := f.sites[spec.Name]; ok {
		return platform.SiteInfo{}, platform.ErrSiteExists
	}
	root := spec.Root
	if root == "" {
		root = "/www/wwwroot/" + spec.Name
	}
	s := platform.SiteInfo{
		Name: spec.Name, Domains: spec.Domains, Root: root, Index: spec.Index,
		Rewrite:    spec.Rewrite,
		ConfigPath: "/etc/nginx/sites-available/minipanel-" + spec.Name + ".conf",
		Enabled:    true, CreatedAt: "2026-11-11T00:00:00Z",
	}
	if v := strings.TrimSpace(spec.PHPVersion); v != "" {
		s.PHPVersion = v
		s.PHPSocket = "/run/php/php" + v + "-fpm.sock"
		s.PHPSocketState = "listening"
	}
	f.sites[spec.Name] = s
	f.created++
	return s, nil
}

func (f *fakeSites) Delete(name string) (platform.SiteInfo, error) {
	if f.deleteErr != nil {
		return platform.SiteInfo{}, f.deleteErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	delete(f.sites, name)
	f.deleted++
	return s, nil
}

func (f *fakeSites) SetPHP(name, version string) (platform.SiteInfo, error) {
	if f.phpErr != nil {
		return platform.SiteInfo{}, f.phpErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.PHPVersion = strings.TrimSpace(version)
	if s.PHPVersion == "" {
		s.PHPSocket = ""
		s.PHPSocketState = ""
		f.phpClears++
	} else {
		s.PHPSocket = "/run/php/php" + s.PHPVersion + "-fpm.sock"
		s.PHPSocketState = "listening"
	}
	f.sites[name] = s
	f.phpSets++
	return s, nil
}

// SetBasics mirrors the provider contract: domains/root/index are replaced,
// PHP and TLS stay as they are.
func (f *fakeSites) SetBasics(name string, domains []string, root string, index []string) (platform.SiteInfo, error) {
	if f.settingsErr != nil {
		return platform.SiteInfo{}, f.settingsErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.Domains = domains
	if root != "" {
		s.Root = root
	}
	s.Index = index
	f.sites[name] = s
	f.settingsSets++
	return s, nil
}

// SetProxy records the target and WebSocket flag. URL validation and the
// rewrite mutual-exclusion rule live in the nginx writer; the HTTP tests only
// need a provider that remembers the call.
func (f *fakeSites) SetProxy(name, target string, websocket bool) (platform.SiteInfo, error) {
	if f.proxyErr != nil {
		return platform.SiteInfo{}, f.proxyErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.ProxyTarget = strings.TrimSpace(target)
	s.ProxyWebSocket = websocket
	f.sites[name] = s
	f.proxySets++
	return s, nil
}

// SetRedirect records the target, status code and keep-path flag. URL
// validation and the three-way location / exclusion live in the nginx writer.
func (f *fakeSites) SetRedirect(name, target string, code int, keepPath bool) (platform.SiteInfo, error) {
	if f.redirectErr != nil {
		return platform.SiteInfo{}, f.redirectErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.RedirectTarget = strings.TrimSpace(target)
	s.RedirectCode = code
	s.RedirectKeepPath = keepPath
	f.sites[name] = s
	f.redirectSets++
	return s, nil
}

func (f *fakeSites) SetHotlink(name string, enabled, allowEmpty bool) (platform.SiteInfo, error) {
	if f.hotlinkErr != nil {
		return platform.SiteInfo{}, f.hotlinkErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.Hotlink = enabled
	s.HotlinkAllowEmpty = enabled && allowEmpty
	f.sites[name] = s
	f.hotlinkSets++
	return s, nil
}

// SetAuth records the username and never keeps the password: the real provider
// hashes it into a 0600 file, and the HTTP contract only promises the username
// back.
func (f *fakeSites) SetAuth(name, username, password string) (platform.SiteInfo, error) {
	if f.authErr != nil {
		return platform.SiteInfo{}, f.authErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.AuthUser = strings.TrimSpace(username)
	f.sites[name] = s
	f.authSets++
	return s, nil
}

// SetRewrite mirrors the provider contract: the id is stored on the row and
// returned to the caller. The real PHP-dependency check lives in nginx; these
// tests only need a provider that records the call.
func (f *fakeSites) SetRewrite(name, preset string) (platform.SiteInfo, error) {
	if f.rewriteErr != nil {
		return platform.SiteInfo{}, f.rewriteErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.Rewrite = preset
	f.sites[name] = s
	f.rewriteSets++
	return s, nil
}

func (f *fakeSites) RewritePresets() []platform.RewritePreset {
	return []platform.RewritePreset{
		{ID: "none", Label: "默认（无重写）", Description: "静态查找"},
		{ID: "wordpress", Label: "WordPress", Description: "回退到 index.php", RequiresPHP: true},
		{ID: "spa", Label: "单页应用（SPA）", Description: "回退到 index.html"},
	}
}

func (f *fakeSites) SetSelfSigned(name string, redirect bool) (platform.SiteInfo, error) {
	if f.tlsErr != nil {
		return platform.SiteInfo{}, f.tlsErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.TLS = &platform.SiteTLSInfo{
		Enabled: true, Redirect: redirect, SelfSigned: true,
		NotAfter: "2027-11-11T00:00:00Z",
	}
	f.sites[name] = s
	f.tlsSets++
	return s, nil
}

func (f *fakeSites) SetCertificate(name, certPEM, keyPEM string, redirect bool) (platform.SiteInfo, error) {
	if f.tlsErr != nil {
		return platform.SiteInfo{}, f.tlsErr
	}
	f.lastCertLen = len(certPEM)
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.TLS = &platform.SiteTLSInfo{
		Enabled: true, Redirect: redirect,
		NotAfter: "2027-11-11T00:00:00Z",
	}
	f.sites[name] = s
	f.tlsSets++
	return s, nil
}

func (f *fakeSites) ObtainACME(_ context.Context, name string, redirect bool) (platform.SiteInfo, error) {
	if f.acmeErr != nil {
		return platform.SiteInfo{}, f.acmeErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.TLS = &platform.SiteTLSInfo{
		Enabled: true, Redirect: redirect, ACME: true,
		NotAfter: "2027-01-11T00:00:00Z",
	}
	f.sites[name] = s
	f.acmeCalls++
	return s, nil
}

func (f *fakeSites) RenewDueACME(context.Context) []platform.ACMEAttempt {
	return nil
}

func (f *fakeSites) ClearCertificate(name string) (platform.SiteInfo, error) {
	if f.tlsErr != nil {
		return platform.SiteInfo{}, f.tlsErr
	}
	s, ok := f.sites[name]
	if !ok {
		return platform.SiteInfo{}, platform.ErrSiteMissing
	}
	s.TLS = nil
	f.sites[name] = s
	f.tlsClears++
	return s, nil
}

type fakeSitePlatform struct {
	t    *testing.T
	site *fakeSites
	// ready=false makes Sites() return !ok, which is what a Windows build or a
	// host without nginx looks like from the handler's perspective.
	ready bool
}

func (f fakeSitePlatform) ID() string { return "linux" }
func (f fakeSitePlatform) Detect() (*platform.Capabilities, error) {
	return siteCaps(f.ready, ""), nil
}
func (f fakeSitePlatform) ConfigDir() string  { return f.t.TempDir() }
func (f fakeSitePlatform) DataDir() string    { return f.t.TempDir() }
func (f fakeSitePlatform) LogDir() string     { return f.t.TempDir() }
func (f fakeSitePlatform) SiteRoot() string   { return "/www/wwwroot" }
func (f fakeSitePlatform) BackupRoot() string { return "/www/backup" }

func (f fakeSitePlatform) Sites() (platform.SiteManager, bool) {
	if !f.ready {
		return nil, false
	}
	return f.site, true
}

func siteCaps(ready bool, reason string) *platform.Capabilities {
	st := platform.StateAvailable
	if !ready {
		st = platform.StateUnavailable
		if reason == "" {
			reason = "本机未检测到 nginx / openresty，站点创建需要一份可写的 nginx 配置目录"
		}
	}
	sslState := platform.StateAvailable
	sslReason := ""
	phpState := platform.StateAvailable
	phpReason := ""
	if !ready {
		sslState = platform.StateUnavailable
		sslReason = "站点证书需要可写的站点 Provider"
		phpState = platform.StateUnavailable
		phpReason = "PHP 版本绑定需要可写的站点 Provider 与 php-fpm 后端"
	}
	return &platform.Capabilities{
		OS: "linux", Arch: "amd64", Hostname: "test-host",
		PHPVersions:    []string{"8.3"},
		PHPFPMVersions: []string{"8.3"},
		Features: map[string]platform.Feature{
			platform.FeatAudit: {State: platform.StateAvailable},
			platform.FeatWebSite: {
				State: st, Reason: reason,
			},
			"site_write": {State: st, Reason: reason},
			platform.FeatPHPVersionSwitch: {
				State: phpState, Reason: phpReason,
				FixAction: "安装 php-fpm 后重载面板",
				Verify:    "minipanel doctor 的 php 行",
			},
			platform.FeatSSL: {
				State: sslState, Reason: sslReason,
				FixAction: "在「网站」页为站点生成自签证书、上传证书链与私钥，或使用 ACME 自动签发",
				Verify:    "GET /api/v1/sites 的 tls.not_after",
			},
		},
	}
}

func newSitePanel(t *testing.T, ready bool) (*panel, *fakeSites) {
	t.Helper()
	fs := newFakeSites()
	p := newPanelWith(t, nil, fakeSitePlatform{t: t, site: fs, ready: ready}, siteCaps(ready, ""))
	p.createAdmin()
	p.visitEntrance()
	p.login()
	return p, fs
}

func TestSiteEndpointsCreateListDelete(t *testing.T) {
	p, fs := newSitePanel(t, true)
	body := `{"name":"blog","domains":["blog.example.com","www.blog.example.com"]}`
	r, resp := p.do(http.MethodPost, "/api/v1/sites", body, p.csrfHeader())
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", r.StatusCode, resp)
	}
	var created platform.SiteInfo
	if err := json.Unmarshal([]byte(resp), &created); err != nil {
		t.Fatalf("create json: %v\n%s", err, resp)
	}
	if created.Name != "blog" || len(created.Domains) != 2 || !created.Enabled {
		t.Errorf("created row = %+v", created)
	}

	r, resp = p.get("/api/v1/sites")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("list = %d %s", r.StatusCode, resp)
	}
	var list struct {
		Total int                 `json:"total"`
		Items []platform.SiteInfo `json:"items"`
	}
	if err := json.Unmarshal([]byte(resp), &list); err != nil {
		t.Fatalf("list json: %v", err)
	}
	if list.Total != 1 || len(list.Items) != 1 || list.Items[0].Name != "blog" {
		t.Errorf("list = %+v", list)
	}

	r, resp = p.do(http.MethodDelete, "/api/v1/sites/blog", "", p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d %s", r.StatusCode, resp)
	}
	if fs.deleted != 1 {
		t.Errorf("provider saw %d deletes, want 1", fs.deleted)
	}
	_, resp = p.get("/api/v1/sites")
	if !strings.Contains(resp, `"total":0`) {
		t.Errorf("list after delete = %s", resp)
	}
}

// TestSiteWritesRequireCSRF is not redundant with the global middleware test:
// these are the first endpoints under a path parameter that a stolen session
// could use to delete something, so the property is re-asserted where it
// matters most.
func TestSiteWritesRequireCSRF(t *testing.T) {
	p, fs := newSitePanel(t, true)
	if r, _ := p.do(http.MethodPost, "/api/v1/sites", `{"name":"blog","domains":["x.example.com"]}`, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("create without csrf = %d, want 403", r.StatusCode)
	}
	if fs.created != 0 {
		t.Error("provider was called without CSRF")
	}
	if r, _ := p.do(http.MethodDelete, "/api/v1/sites/blog", "", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("delete without csrf = %d, want 403", r.StatusCode)
	}
}

func TestSiteCreateMapsProviderErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		kind string
	}{
		{fmt.Errorf("%w：名字不合法", platform.ErrSiteInvalid), http.StatusBadRequest, "invalid_site"},
		{platform.ErrSiteExists, http.StatusConflict, "site_exists"},
		{fmt.Errorf("%w：nginx: [emerg] bad", platform.ErrSiteRefused), http.StatusUnprocessableEntity, "nginx_rejected"},
	}
	for _, c := range cases {
		p, fs := newSitePanel(t, true)
		fs.createErr = c.err
		r, body := p.do(http.MethodPost, "/api/v1/sites",
			`{"name":"blog","domains":["x.example.com"]}`, p.csrfHeader())
		if r.StatusCode != c.code || !strings.Contains(body, `"kind":"`+c.kind+`"`) {
			t.Errorf("err %v = %d %s, want %d %s", c.err, r.StatusCode, body, c.code, c.kind)
		}
	}
}

func TestSiteDeleteUnknownIs404(t *testing.T) {
	p, _ := newSitePanel(t, true)
	r, body := p.do(http.MethodDelete, "/api/v1/sites/ghost", "", p.csrfHeader())
	if r.StatusCode != http.StatusNotFound || !strings.Contains(body, `"kind":"not_found"`) {
		t.Errorf("delete unknown = %d %s", r.StatusCode, body)
	}
}

// TestSiteEndpointsRefuseWhenCapabilityIsUnavailable: the reason the operator
// sees must be the bitmap's own sentence, not a new one invented here.
func TestSiteEndpointsRefuseWhenCapabilityIsUnavailable(t *testing.T) {
	fs := newFakeSites()
	reason := "本机未检测到 nginx / openresty，站点创建需要一份可写的 nginx 配置目录"
	p := newPanelWith(t, nil, fakeSitePlatform{t: t, site: fs, ready: false}, siteCaps(false, reason))
	p.createAdmin()
	p.visitEntrance()
	p.login()

	for _, req := range []struct {
		method, path, body string
		hdr                map[string]string
	}{
		{http.MethodGet, "/api/v1/sites", "", nil},
		{http.MethodPost, "/api/v1/sites", `{"name":"blog","domains":["x.example.com"]}`, p.csrfHeader()},
	} {
		r, body := p.do(req.method, req.path, req.body, req.hdr)
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", req.method, req.path, r.StatusCode)
		}
		if !strings.Contains(body, reason) || !strings.Contains(body, `"kind":"capability"`) {
			t.Errorf("%s %s reason not passed through: %s", req.method, req.path, body)
		}
	}
	if fs.created != 0 {
		t.Error("provider was called while the capability was unavailable")
	}
}

// TestSiteWritesAreAudited: the M2 acceptance list says every write joins the
// audit trail. The middleware does that for all non-GETs, so this is a
// regression guard on the routes being registered inside the authenticated
// group rather than somewhere else.
func TestSiteWritesAreAudited(t *testing.T) {
	p, _ := newSitePanel(t, true)
	if r, body := p.do(http.MethodPost, "/api/v1/sites",
		`{"name":"blog","domains":["blog.example.com"]}`, p.csrfHeader()); r.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", r.StatusCode, body)
	}
	if r, body := p.do(http.MethodDelete, "/api/v1/sites/blog", "", p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d %s", r.StatusCode, body)
	}
	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var sawCreate, sawDelete bool
	for _, e := range entries {
		switch e.Action {
		case "POST /api/v1/sites":
			sawCreate = true
			if !strings.Contains(e.Target, "/api/v1/sites") {
				t.Errorf("create audit target = %q", e.Target)
			}
		case "DELETE /api/v1/sites/{name}":
			sawDelete = true
		}
	}
	if !sawCreate || !sawDelete {
		t.Errorf("audit rows missing (create=%v delete=%v): %+v", sawCreate, sawDelete, entries)
	}
}
