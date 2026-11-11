package nginx

import (
	"fmt"
	"strings"
)

// RewritePreset is one locally bundled rewrite template. The set is fixed in
// this binary on purpose: a "rewrite rule library" that downloads templates at
// runtime would turn a site form into an arbitrary-config fetch, and the
// project's design rules reject that (docs/功能设计.md §3.2 and §8.1).
//
// RequiresPHP is part of the contract rather than a UI hint. A template that
// forwards to /index.php on a static site is not a harmless preference: nginx
// would return the PHP source as text, which is the same leak the default-index
// check already refuses.
type RewritePreset struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	RequiresPHP bool   `json:"requires_php"`
}

// rewritePresets is the complete local template set. Order is stable so the
// selector does not jump between page loads and the test can compare it.
var rewritePresets = []RewritePreset{
	{
		ID: "none", Label: "默认（无重写）",
		Description: "只做 $uri / $uri/ 的静态查找，找不到返回 404。",
	},
	{
		ID: "wordpress", Label: "WordPress",
		Description: "固定链接交给 /index.php?$args；需要站点已绑定 PHP。",
		RequiresPHP: true,
	},
	{
		ID: "laravel", Label: "Laravel",
		Description: "所有不存在的路径交给 /index.php?$query_string；需要站点已绑定 PHP。",
		RequiresPHP: true,
	},
	{
		ID: "thinkphp", Label: "ThinkPHP",
		Description: "不存在的路径交给 /index.php?s=$uri&$args；需要站点已绑定 PHP。",
		RequiresPHP: true,
	},
	{
		ID: "spa", Label: "单页应用（SPA）",
		Description: "不存在的路径回退到 /index.html，由前端路由接管；可用于纯静态站点。",
	},
}

// RewritePresets returns a copy: callers may sort or annotate the slice without
// mutating the package-level contract.
func RewritePresets() []RewritePreset {
	out := make([]RewritePreset, len(rewritePresets))
	copy(out, rewritePresets)
	return out
}

// normalizeRewrite maps the empty/whitespace value onto "none". No other
// aliases are accepted: the id goes into the marker and is the only durable
// record of what the panel wrote, so it must stay a closed vocabulary.
func normalizeRewrite(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return "none"
	}
	return id
}

func rewritePreset(id string) (RewritePreset, bool) {
	id = normalizeRewrite(id)
	for _, p := range rewritePresets {
		if p.ID == id {
			return p, true
		}
	}
	return RewritePreset{}, false
}

// validateRewrite rejects unknown ids and PHP-dependent templates on a site
// without a PHP handler. The id is not a filename or a config fragment, so
// there is nothing to escape; the allow-list is the security boundary.
func validateRewrite(id string, phpBound bool) error {
	p, ok := rewritePreset(id)
	if !ok {
		return fmt.Errorf("%w：伪静态规则 %q 不在本机模板库中", ErrInvalid, id)
	}
	if p.RequiresPHP && !phpBound {
		return fmt.Errorf("%w：伪静态规则 %q 需要站点已绑定 PHP；否则 nginx 会把 index.php 当文本返回", ErrInvalid, p.ID)
	}
	return nil
}

// rewriteLocation is the one place a preset becomes nginx syntax. Keeping the
// mapping here (instead of interpolating operator input) is what makes the
// allow-list meaningful: only these exact lines can ever be written.
func rewriteLocation(s Site) string {
	switch normalizeRewrite(s.Rewrite) {
	case "wordpress":
		return "try_files $uri $uri/ /index.php?$args;"
	case "laravel":
		return "try_files $uri $uri/ /index.php?$query_string;"
	case "thinkphp":
		return "try_files $uri $uri/ /index.php?s=$uri&$args;"
	case "spa":
		return "try_files $uri $uri/ /index.html;"
	default:
		return "try_files $uri $uri/ =404;"
	}
}

// SetRewrite replaces the site's rewrite preset. It is a full replacement, not
// a patch: "none" removes the template. The write uses the same
// test-before-reload protocol as every other vhost change.
func (m *Manager) SetRewrite(name, preset string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	preset = normalizeRewrite(preset)
	if err := validateRewrite(preset, site.PHPVersion != ""); err != nil {
		return Site{}, err
	}
	site.Rewrite = preset
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
