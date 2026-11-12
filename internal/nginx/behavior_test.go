package nginx

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// 第十七片 is two server-level switches. These tests pin the exact directive,
// the marker round-trip, the coexistence with the location owners, the rollback,
// and — for force-HTTPS — the precondition that refuses a redirect without a
// certificate and toggles the port-80 block when a certificate exists.

func TestSetAutoIndexRendersDirectiveAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetAutoIndex("shop", true)
	if err != nil {
		t.Fatalf("SetAutoIndex: %v", err)
	}
	if !site.AutoIndex {
		t.Errorf("returned AutoIndex = false")
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want test then reload", rec.cmds)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("shop"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{"    autoindex on;\n", `"autoindex":true`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("autoindex config missing %q\n%s", want, body)
		}
	}
	// The default index lookup must still be there — autoindex is additive.
	if !strings.Contains(string(body), "index index.html index.htm;") {
		t.Errorf("autoindex removed the default index list\n%s", body)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 || !list[0].AutoIndex {
		t.Fatalf("marker round-trip AutoIndex = %+v (%v)", list, err)
	}

	if _, err := m.SetAutoIndex("shop", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("shop"))
	if strings.Contains(string(body), "autoindex on") || strings.Contains(string(body), `"autoindex":true`) {
		t.Errorf("disabling autoindex left a directive or marker field behind\n%s", body)
	}
	list, _ = m.List()
	if len(list) != 1 || list[0].AutoIndex {
		t.Errorf("marker after disabling autoindex = %+v", list)
	}
}

func TestSetAutoIndexCoexistsWithProxyAndHotlink(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "api", Domains: []string{"api.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetProxy("api", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if _, err := m.SetAutoIndex("api", true); err != nil {
		t.Fatalf("SetAutoIndex over proxy: %v", err)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("api"))
	if !strings.Contains(string(body), "autoindex on;") {
		t.Errorf("proxy site lost autoindex\n%s", body)
	}
	if !strings.Contains(string(body), "proxy_pass") {
		t.Errorf("autoindex removed the proxy location\n%s", body)
	}
	// Turning it back off must keep the proxy intact.
	if _, err := m.SetAutoIndex("api", false); err != nil {
		t.Fatalf("disable over proxy: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("api"))
	if strings.Contains(string(body), "autoindex on") || !strings.Contains(string(body), "proxy_pass") {
		t.Errorf("disabling autoindex disturbed the proxy site\n%s", body)
	}
}

func TestSetAutoIndexRollsBackWhenNginxRefuses(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	rec.cmds = nil
	rec.failOn = "-t"
	if _, err := m.SetAutoIndex("blog", true); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	if len(rec.cmds) != 1 || rec.cmds[0] != "nginx -t" {
		t.Errorf("commands = %v, want only the failing test (no reload)", rec.cmds)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("rejected autoindex changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestSetForceHTTPSRequiresEnabledCertificate(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "plain", Domains: []string{"plain.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("plain"))
	if _, err := m.SetForceHTTPS("plain", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("force-HTTPS without TLS err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("plain"))
	if string(after) != string(before) {
		t.Errorf("rejected force-HTTPS changed the plain-HTTP config\nbefore:\n%s\nafter:\n%s", before, after)
	}
	// Disabling on a plain site is a no-op success — there is nothing to remove.
	if _, err := m.SetForceHTTPS("plain", false); err != nil {
		t.Fatalf("disable on plain site: %v", err)
	}
}

func TestSetForceHTTPTogglesRedirectBlock(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "secure", Domains: []string{"secure.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// TLS on, redirect off: the 443 server also listens on 80, no 301 block.
	if _, err := m.SetSelfSigned("secure", false); err != nil {
		t.Fatalf("SetSelfSigned: %v", err)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("secure"))
	if strings.Contains(string(body), "return 301 https://") {
		t.Fatalf("redirect present before it was enabled\n%s", body)
	}
	rec.cmds = nil
	site, err := m.SetForceHTTPS("secure", true)
	if err != nil {
		t.Fatalf("SetForceHTTPS: %v", err)
	}
	if site.TLS == nil || !site.TLS.Redirect {
		t.Fatalf("returned TLS redirect flag = %+v", site.TLS)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("secure"))
	if !strings.Contains(string(body), "return 301 https://$host$request_uri;") {
		t.Errorf("force-HTTPS on did not render the redirect block\n%s", body)
	}
	// With the redirect on there are exactly two server blocks (the port-80
	// redirector and the 443 TLS server); the TLS server must no longer carry a
	// plain listen 80, or ACME-style traffic would be served un-redirected.
	if got := strings.Count(string(body), "server {\n"); got != 2 {
		t.Errorf("redirect-on server block count = %d, want 2\n%s", got, body)
	}
	if tlsIdx := strings.Index(string(body), "listen 443 ssl;"); tlsIdx >= 0 &&
		strings.Contains(string(body)[tlsIdx:], "    listen 80;") {
		t.Errorf("TLS server still listens on 80 with the redirect block present\n%s", body)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].TLS == nil || !list[0].TLS.Redirect {
		t.Errorf("marker round-trip tls.redirect = %+v", list)
	}

	if _, err := m.SetForceHTTPS("secure", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("secure"))
	if strings.Contains(string(body), "return 301 https://") {
		t.Errorf("disabling force-HTTPS left the redirect block\n%s", body)
	}
	if !strings.Contains(string(body), "listen 80;") {
		t.Errorf("disabling force-HTTPS removed the plain-HTTP listener\n%s", body)
	}
}
