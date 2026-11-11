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
	PHPVersion     string `json:"php_version,omitempty"`
	PHPSocket      string `json:"php_socket,omitempty"`
	// PHPSocketState is the live state of PHPSocket (listening / idle / absent /
	// not_socket / unknown), computed on every read. It is not persisted: "the
	// site points at 8.3" and "php8.3-fpm is answering" are two separate facts,
	// and this is the second one.
	PHPSocketState string `json:"php_socket_state,omitempty"`
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
