package platform

import "errors"

// SiteSpec and SiteInfo are the platform-neutral shapes the HTTP layer speaks.
// The nginx writer and any future Apache/IIS provider convert to and from
// these, so internal/api never imports a provider package and the selector
// stays "ask the platform".
type SiteSpec struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Root    string   `json:"root"`
}

type SiteInfo struct {
	Name       string   `json:"name"`
	Domains    []string `json:"domains"`
	Root       string   `json:"root"`
	ConfigPath string   `json:"config_path"`
	Enabled    bool     `json:"enabled"`
	CreatedAt  string   `json:"created_at"`
}

// SiteManager is the write side of FeatWebSite. It is deliberately small: the
// panel creates static sites, lists what it created, and deletes them. Editing
// domains, PHP binding and certificates are later slices with their own
// endpoints, and inventing them now would be the clickable-nothing this
// project refuses.
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
	ErrSiteExists  = errors.New("同名站点已存在")
	ErrSiteMissing = errors.New("面板没有管理这个站点（不存在，或不是面板创建的）")
	ErrSiteInvalid = errors.New("站点参数不合法")
	ErrSiteRefused = errors.New("写入被 nginx 拒绝，已回滚")
)
