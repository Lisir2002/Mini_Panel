package nginx

import "fmt"

// Hotlink protection is the eleventh slice of M2. The operator only chooses
// whether it is on and whether a missing Referer is allowed; the extension list,
// the valid_referers arguments and the rejection status are constants. The block
// is a regex location, not `location /`, so rewrite templates keep working.
const hotlinkExtensionPattern = `\.(jpg|jpeg|png|gif|webp|avif|svg|ico|bmp|css|js|mjs|woff|woff2|ttf|otf|eot|mp4|webm|mp3|ogg|oga|wav)$`

// hotlinkLocationBody renders the fixed Referer check. `none` allows requests
// without a Referer (address bar, curl, privacy browsers); `blocked` allows the
// scheme-stripped form. Both are omitted when the operator requires a same-site
// Referer for every asset. `server_names` covers every domain in server_name,
// including wildcards, so no request-supplied host list is ever written.
func hotlinkLocationBody(s Site) string {
	referers := "server_names"
	if s.HotlinkAllowEmpty {
		referers = "none blocked server_names"
	}
	return fmt.Sprintf(`    location ~* %s {
        valid_referers %s;
        if ($invalid_referer) {
            return 403;
        }
    }
`, hotlinkExtensionPattern, referers)
}

// SetHotlink enables, replaces or disables hotlink protection. Disabling is
// always allowed, and a proxy or site-wide redirect cannot be active while it is
// enabled: those two take over `location /`, which would make the local asset
// block either unreachable or a surprising interception in front of the upstream.
func (m *Manager) SetHotlink(name string, enabled, allowEmpty bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if enabled {
		if site.ProxyTarget != "" {
			return Site{}, fmt.Errorf("%w：站点正在使用反向代理，静态资源不在本机；先清除代理再启用防盗链", ErrInvalid)
		}
		if site.RedirectTarget != "" {
			return Site{}, fmt.Errorf("%w：站点正在整站跳转，静态资源由目标站点提供；先清除跳转再启用防盗链", ErrInvalid)
		}
	}
	site.Hotlink = enabled
	site.HotlinkAllowEmpty = enabled && allowEmpty
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
