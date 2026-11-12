package platform

import (
	"context"
	"errors"
)

// SiteSpec and SiteInfo are the platform-neutral shapes the HTTP layer speaks.
// The nginx writer and any future Apache/IIS provider convert to and from
// these, so internal/api never imports a provider package and the selector
// stays "ask the platform".
//
// PHPVersion is the version the operator selected. The provider resolves it to
// a socket after checking that the version really exposes fpm; the API never
// supplies a path.
type SiteSpec struct {
	Name       string   `json:"name"`
	Domains    []string `json:"domains"`
	Root       string   `json:"root"`
	Index      []string `json:"index,omitempty"`
	Rewrite    string   `json:"rewrite,omitempty"`
	PHPVersion string   `json:"php_version,omitempty"`
}

type SiteInfo struct {
	Name       string       `json:"name"`
	Domains    []string     `json:"domains"`
	Root       string       `json:"root"`
	ConfigPath string       `json:"config_path"`
	Enabled    bool         `json:"enabled"`
	CreatedAt  string       `json:"created_at"`
	TLS        *SiteTLSInfo `json:"tls,omitempty"`
	// Index is the site's custom document-index list; absent means the panel's
	// default (index.php first for PHP sites, otherwise index.html/index.htm).
	Index []string `json:"index,omitempty"`
	// Rewrite is the id of a bundled rewrite template ("none" for the default
	// static lookup). The set is exposed by SiteRewriteManager so the UI and
	// the provider cannot drift.
	Rewrite string `json:"rewrite,omitempty"`
	// ProxyTarget is the validated upstream URL when the site is a reverse
	// proxy; empty means no proxy. ProxyWebSocket says whether the fixed
	// directive block forwards Upgrade/Connection headers.
	ProxyTarget    string `json:"proxy_target,omitempty"`
	ProxyWebSocket bool   `json:"proxy_websocket,omitempty"`
	// ProxyUpstreams is the load-balanced form of the same proxy: a table of
	// http backends with weights, mutually exclusive with ProxyTarget (both
	// own `location /`). ProxyLBMethod is the balancing method; empty means
	// nginx's default round robin. The provider owns the http-level upstream
	// block, so callers only ever name backends, never nginx text.
	ProxyUpstreams []SiteProxyUpstream `json:"proxy_upstreams,omitempty"`
	ProxyLBMethod  string              `json:"proxy_lb_method,omitempty"`
	// RedirectTarget is the validated absolute URL when the site redirects
	// every request; empty means no redirect. RedirectCode is 301 or 302 and
	// RedirectKeepPath says whether the original request path is appended.
	// RedirectPaths is a table of exact path exceptions rendered before the
	// catch-all; an empty table means no exceptions.
	RedirectTarget   string             `json:"redirect_target,omitempty"`
	RedirectCode     int                `json:"redirect_code,omitempty"`
	RedirectKeepPath bool               `json:"redirect_keep_path,omitempty"`
	RedirectPaths    []SiteRedirectRule `json:"redirect_paths,omitempty"`
	// ErrorPages maps HTTP error statuses to URIs under the site root,
	// rendered as fixed server-level error_page directives. An empty table
	// means nginx's built-in error responses.
	ErrorPages []SiteErrorPageRule `json:"error_pages,omitempty"`
	// Hotlink is the fixed Referer check for static assets; HotlinkAllowEmpty
	// says whether requests without a Referer are allowed through. Both are
	// omitted until hotlink protection is enabled.
	Hotlink           bool `json:"hotlink,omitempty"`
	HotlinkAllowEmpty bool `json:"hotlink_allow_empty,omitempty"`
	// AutoIndex is the server-level directory-listing switch. It is false when
	// the site serves nginx's default 403/404 for a bare directory. Force-HTTPS
	// is not a separate field here: it is `TLS.redirect`, which the certificate
	// endpoints already set and the standalone PUT /force-https only toggles.
	AutoIndex bool `json:"autoindex,omitempty"`
	// AuthUser is the Basic Auth username when the whole site is password
	// protected. The password itself is never stored in SiteInfo: only the
	// provider's 0600 file holds a {SHA} hash, and no endpoint returns it.
	AuthUser string `json:"auth_user,omitempty"`
	// RealIPFrom lists the trusted proxy addresses/CIDRs; RealIPHeader names the
	// forwarding header. They are empty when the site logs the peer address.
	RealIPFrom   []string `json:"real_ip_from,omitempty"`
	RealIPHeader string   `json:"real_ip_header,omitempty"`
	// Limits is the site's traffic ceiling; nil means the site is not limited.
	// The provider owns the shared-memory zone definitions that go with it.
	Limits     *SiteTrafficLimit `json:"limits,omitempty"`
	PHPVersion string            `json:"php_version,omitempty"`
	PHPSocket  string            `json:"php_socket,omitempty"`
	// PHPSocketState is the live state of PHPSocket (listening / idle / absent /
	// not_socket / unknown), computed on every read. It is not persisted: "the
	// site points at 8.3" and "php8.3-fpm is answering" are two separate facts,
	// and this is the second one.
	PHPSocketState string `json:"php_socket_state,omitempty"`
	// Group and Note are the operator's panel-side annotations, keyed by site
	// name in the store and joined onto the list by the HTTP layer. The provider
	// itself never sets them (nginx knows nothing about them), so every write
	// response comes back with these empty and the front end re-reads the list
	// to refresh them.
	Group string `json:"group,omitempty"`
	Note  string `json:"note,omitempty"`
}

// SiteTLSInfo is the platform-neutral certificate state of one site.
type SiteTLSInfo struct {
	Enabled    bool   `json:"enabled"`
	Redirect   bool   `json:"redirect"`
	SelfSigned bool   `json:"self_signed"`
	ACME       bool   `json:"acme"`
	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	Error      string `json:"error,omitempty"`
}

// SiteRedirectRule is one exact-path exception in a site's redirect table. The
// provider validates both path and target and renders a fixed `location =`
// block; callers cannot submit nginx text.
type SiteRedirectRule struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	Code   int    `json:"code"`
}

// SiteErrorPageRule maps one HTTP error status to a URI inside the site root.
// The provider validates the closed status vocabulary and the path shape and
// renders a fixed `error_page` line; callers cannot submit nginx text.
type SiteErrorPageRule struct {
	Code int    `json:"code"`
	Path string `json:"path"`
}

// SiteProxyUpstream is one backend in a site's load-balanced proxy table. The
// provider validates the URL (http only, host:port, no path), the weight
// bounds and the table size, and renders the http-level upstream block itself.
type SiteProxyUpstream struct {
	Target string `json:"target"`
	Weight int    `json:"weight,omitempty"`
}

// SiteTrafficLimit is one site's traffic ceiling in platform-neutral form. The
// provider validates the rate shape and the numeric bounds, derives the zone
// names from the site name, and writes the nginx zone definitions themselves —
// they have to live outside the vhost, so a caller cannot name a zone.
type SiteTrafficLimit struct {
	// RequestRate is a rate the provider understands, e.g. "10r/s" or "200r/m".
	// Empty means no request-rate limit.
	RequestRate string `json:"request_rate,omitempty"`
	// Burst is only meaningful with a request rate; nginx takes it on the
	// limit_req line together with a fixed nodelay.
	Burst int `json:"burst,omitempty"`
	// Connections caps concurrent connections per client address. 0 means none.
	Connections int `json:"connections,omitempty"`
	// Status is the status nginx returns when a limit is exceeded. Only 429 and
	// 503 are accepted; 0 means nginx's own default (503).
	Status int `json:"status,omitempty"`
}

// SiteManager is the write side of FeatWebSite. It is deliberately small: the
// panel creates static sites, lists what it created, and deletes them. PHP
// binding, certificate controls and basic-settings editing are separate
// optional interfaces with their own endpoints.
type SiteManager interface {
	List() ([]SiteInfo, error)
	Create(SiteSpec) (SiteInfo, error)
	Delete(name string) (SiteInfo, error)
}

// SiteProvider is implemented by platforms that ship a site writer. It is a
// separate optional interface rather than a Platform method so Windows builds
// keep compiling without an nginx implementation, while the bitmap still
// tells the truth about that host.
type SiteProvider interface {
	Sites() (SiteManager, bool)
}

// SitePHPManager is the optional version-binding half of a site writer. It is
// separate from SiteManager because switching PHP is a second kind of write
// (rewrite the handler, test, reload) with a host-dependent precondition: the
// requested version must expose fpm on this machine.
type SitePHPManager interface {
	SetPHP(name, version string) (SiteInfo, error)
}

// SiteSettingsManager is the optional "edit the basics" half of a site writer:
// replace domains, document root and the default-index list. It is separate
// from SiteManager for the same reason as SitePHPManager: an older provider can
// keep compiling and the UI can say "this host cannot edit sites yet" from a
// missing interface instead of showing a form that writes nothing.
type SiteSettingsManager interface {
	SetBasics(name string, domains []string, root string, index []string) (SiteInfo, error)
}

// RewritePreset is the platform-neutral view of one locally bundled rewrite
// template. RequiresPHP tells the UI (and the server-side validator) that the
// template's fallback is a PHP script, which must never be served as text.
type RewritePreset struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	RequiresPHP bool   `json:"requires_php"`
}

// SiteRewriteManager is the optional "rewrite templates" half of a site
// writer. The template set is read from the provider rather than duplicated in
// the front end, so adding a template cannot produce a UI option the backend
// rejects (or a backend template with no way to select it).
type SiteRewriteManager interface {
	SetRewrite(name, preset string) (SiteInfo, error)
	RewritePresets() []RewritePreset
}

// SiteProxyManager is the optional reverse-proxy half of a site writer. The
// operator supplies one upstream URL; the provider validates it into
// scheme/host/port/path and renders a fixed directive block. Clearing (empty
// target) is always allowed so an operator can recover a site whose upstream
// disappeared, even if the rest of the site writer is degraded.
type SiteProxyManager interface {
	SetProxy(name, target string, websocket bool) (SiteInfo, error)
}

// SiteProxyLBManager is the optional load-balanced proxy half of a site
// writer. It is separate from SiteProxyManager for the same reason
// SiteTrafficLimitManager is separate: nginx defines upstream blocks outside
// any server block, so a host whose config has no wildcard http-level include
// cannot offer this feature at all, and that reason has to reach the UI. The
// operator supplies complete backend tables plus a method from the provider's
// closed vocabulary; an empty table is always an allowed clear operation.
// Setting a single target via SetProxy clears the table, and vice versa.
type SiteProxyLBManager interface {
	SetProxyUpstreams(name string, upstreams []SiteProxyUpstream, method string, websocket bool) (SiteInfo, error)
}

// SiteRedirectManager is the optional site-wide redirect half of a site writer.
// The operator supplies one absolute URL, a 301/302 status and whether the
// original path is preserved; the provider validates the URL and renders a
// fixed `return` line. Clearing (empty target) is always allowed.
type SiteRedirectManager interface {
	SetRedirect(name, target string, code int, keepPath bool) (SiteInfo, error)
}

// SiteRedirectPathManager is the optional exact-path redirect table. The
// operator supplies complete rules (path + absolute target + 301/302); the
// provider normalizes and renders fixed `location =` blocks. An empty table is
// always an allowed clear operation.
type SiteRedirectPathManager interface {
	SetRedirectPaths(name string, rules []SiteRedirectRule) (SiteInfo, error)
}

// SiteErrorPageManager is the optional custom error page table. The operator
// supplies complete rules (status + in-site URI); the provider normalizes and
// renders fixed server-level error_page directives. An empty table is always
// an allowed clear operation.
type SiteErrorPageManager interface {
	SetErrorPages(name string, rules []SiteErrorPageRule) (SiteInfo, error)
}

// SiteHotlinkManager is the optional hotlink-protection half of a site writer.
// The operator only chooses whether it is on and whether a missing Referer is
// allowed; the extension list, valid_referers arguments and rejection status are
// fixed by the provider. Disabling is always allowed.
type SiteHotlinkManager interface {
	SetHotlink(name string, enabled, allowEmpty bool) (SiteInfo, error)
}

// SiteAuthManager is the optional HTTP Basic Auth half of a site writer. The
// operator supplies a username and a password; the provider hashes it into its
// own 0600 file, renders the fixed auth_basic directives and never accepts a
// config fragment. Clearing (empty username and password) is always allowed so
// a site whose password was lost can be recovered.
type SiteAuthManager interface {
	SetAuth(name, username, password string) (SiteInfo, error)
}

// SiteRealIPManager is the optional trusted-proxy half of a site writer. The
// caller supplies the peers whose forwarding header is trusted and which of the
// two supported headers to read; the provider validates both and renders the
// fixed set_real_ip_from / real_ip_header block. Clearing is always allowed.
type SiteRealIPManager interface {
	SetRealIP(name string, from []string, header string) (SiteInfo, error)
}

// SiteTrafficLimitManager is the optional traffic-limit half of a site writer.
// It is separate because a provider needs somewhere to put an http-level
// include: nginx defines the shared-memory zones outside any server block, so
// a host whose config has no wildcard include cannot offer this feature at all,
// and that reason has to reach the UI instead of a half-written config.
// Clearing (an empty limit) is always allowed.
type SiteTrafficLimitManager interface {
	SetLimits(name string, limit SiteTrafficLimit) (SiteInfo, error)
}

// SiteBehaviorManager is the optional pair of server-level behaviour switches:
// directory listing (autoindex) and the HTTP-to-HTTPS redirect. Both are fixed
// directives the provider renders — a caller only ever flips a boolean. It is a
// single interface rather than two because both writes are the same kind of
// operation (read the vhost, flip one server-level fact, test, reload), and a
// provider that can do one can do the other. Force-HTTPS has its own precondition
// (an enabled certificate) enforced in the provider, so a host without TLS tooling
// still cannot be talked into a broken config.
type SiteBehaviorManager interface {
	SetAutoIndex(name string, enabled bool) (SiteInfo, error)
	SetForceHTTPS(name string, enabled bool) (SiteInfo, error)
}

// SiteLogInfo is one read of a site's log tail. Exists=false is a real answer
// (the vhost has not served a request since per-site logs were enabled), not
// an error; Lines is always a non-nil slice so the page can render it directly.
type SiteLogInfo struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Path      string   `json:"path"`
	Exists    bool     `json:"exists"`
	Size      int64    `json:"size"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}

// SiteLogManager is the optional per-site log side: a read-only tail viewer
// plus the one-time migration that gives pre-existing panel vhosts their log
// directives. It is one interface because a provider that can read the logs
// is exactly the provider that wrote them; a platform without it answers 403
// capability with a reason instead of showing a dead button.
type SiteLogManager interface {
	MigrateSiteLogs() error
	SiteLog(name, kind string, lines int) (SiteLogInfo, error)
}

// SiteTLSManager is the optional certificate side of a site writer. Manual
// upload, self-signed generation and clearing all go through it. A platform
// without this interface cannot offer the HTTPS controls, and the UI hides them
// behind the same bitmap.
type SiteTLSManager interface {
	SetSelfSigned(name string, redirect bool) (SiteInfo, error)
	SetCertificate(name, certPEM, keyPEM string, redirect bool) (SiteInfo, error)
	ClearCertificate(name string) (SiteInfo, error)
}

// SiteACMEManager is the automatic-issuance half. It is separate from
// SiteTLSManager because issuing an HTTP-01 certificate is a long network
// operation with its own failure modes, while the manual endpoints stay fast and
// local. The renewal method is called by the panel's scheduler, not by an HTTP
// handler, so it returns per-site results instead of one error.
type SiteACMEManager interface {
	ObtainACME(ctx context.Context, name string, redirect bool) (SiteInfo, error)
	RenewDueACME(ctx context.Context) []ACMEAttempt
}

// ACMEAttempt is one renewal decision. Error is the operator-readable failure;
// a successful attempt is one row with Renewed=true.
type ACMEAttempt struct {
	Name    string `json:"name"`
	Renewed bool   `json:"renewed"`
	Error   string `json:"error,omitempty"`
}

// WebServerProvider exposes the config test/reload surface of the detected
// web server. The API uses it right now only to report readiness; M2's later
// slices will call TestConfig before every write, and the provider has to be
// reachable from the platform for that to stay in one place.
type WebServerProvider interface {
	WebServer() (WebServerCtl, bool)
}

// The API maps these onto HTTP status codes. They are sentinel errors so a
// provider can wrap its own detail while callers still branch on the kind.
var (
	ErrSiteExists      = errors.New("同名站点已存在")
	ErrSiteMissing     = errors.New("面板没有管理这个站点（不存在，或不是面板创建的）")
	ErrSiteInvalid     = errors.New("站点参数不合法")
	ErrSiteRefused     = errors.New("写入被 nginx 拒绝，已回滚")
	ErrSiteTLSInvalid  = errors.New("站点证书不合法")
	ErrSitePHP         = errors.New("该 PHP 版本不能绑定到站点")
	ErrACMEUnsupported = errors.New("ACME HTTP-01 不支持该站点")
	ErrACMEFailed      = errors.New("ACME 签发失败")
)
