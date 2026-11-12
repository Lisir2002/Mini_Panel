package nginx

import "fmt"

// 第十七片 gives two server-level behaviour switches that a BaoTa-style panel
// exposes on every site: directory listing (autoindex) and forcing plain-HTTP
// requests to HTTPS. Both are fixed nginx directives rather than anything a
// caller can type — the panel only ever toggles a boolean and re-renders the
// whole vhost through the shared test-before-reload path.

// SetAutoIndex turns nginx's server-level `autoindex` on or off for one
// panel-owned site. It changes only what happens to a request that resolves to
// a directory with no default document; the index list, the PHP handler, the
// proxy, rewrite, redirect, hotlink, auth, real-IP and traffic-limit blocks are
// untouched, and because the directive is server-level it never owns
// `location /`. Turning it off is always allowed, including while other
// features are active.
func (m *Manager) SetAutoIndex(name string, enabled bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	site.AutoIndex = enabled
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}

// SetForceHTTPS turns the site's HTTP-to-HTTPS redirect on or off. It is the
// standalone control for a state the certificate endpoints already carry
// (`TLSInfo.Redirect`): enabling it renders the port-80 redirect block and drops
// `listen 80` from the TLS server, disabling it does the reverse. Because the
// redirect is meaningless without a certificate, a site whose HTTPS is not
// enabled is refused with a reason instead of writing a config that would make
// nginx listen on 443 with no key — forcing HTTPS is only ever honest about an
// HTTPS site. Clearing is always allowed for a site that has HTTPS.
func (m *Manager) SetForceHTTPS(name string, enabled bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if enabled {
		if site.TLS == nil || !site.TLS.Enabled {
			return Site{}, fmt.Errorf("%w：强制 HTTPS 需要先为该站点启用 HTTPS（自签、上传或 ACME 均可）", ErrInvalid)
		}
	}
	if site.TLS == nil {
		// Disabling force-HTTPS on a plain-HTTP site is already its state; there
		// is no redirect to remove and nothing to rewrite.
		return site, nil
	}
	site.TLS.Redirect = enabled
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
