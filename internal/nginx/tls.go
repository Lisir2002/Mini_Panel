package nginx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrTLSInvalid means the certificate or key did not pass the checks the
// writer can make without nginx: parseable PEM, matching pair, inside its
// validity window, and actually covering every domain the site claims.
var ErrTLSInvalid = errors.New("站点证书不合法")

// TLSInfo is the certificate state reported to the UI. Error is populated when
// the marker says TLS is on but the files cannot be read; the site is still
// listed (a missing certificate is a fact to show, not a reason to hide the
// site), and the next config test will fail loudly.
type TLSInfo struct {
	Enabled    bool   `json:"enabled"`
	Redirect   bool   `json:"redirect"`
	SelfSigned bool   `json:"self_signed"`
	ACME       bool   `json:"acme"`
	CertPath   string `json:"cert_path,omitempty"`
	KeyPath    string `json:"key_path,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	Error      string `json:"error,omitempty"`
}

// markerTLS is what gets persisted in the vhost marker. The paths are recorded
// for diagnostics but are never trusted on read: the writer always derives
// them from CertDir + site name, so a tampered marker cannot point nginx at an
// arbitrary file.
type markerTLS struct {
	Enabled    bool   `json:"enabled"`
	Redirect   bool   `json:"redirect,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
	ACME       bool   `json:"acme,omitempty"`
	Cert       string `json:"cert,omitempty"`
	Key        string `json:"key,omitempty"`
}

func markerFromTLS(name string, t *TLSInfo) *markerTLS {
	if t == nil || !t.Enabled {
		return nil
	}
	return &markerTLS{
		Enabled: true, Redirect: t.Redirect, SelfSigned: t.SelfSigned, ACME: t.ACME,
		Cert: t.CertPath, Key: t.KeyPath,
	}
}

func (m *Manager) certPaths(name string) (cert, key string) {
	return filepath.Join(m.CertDir, name+".crt"), filepath.Join(m.CertDir, name+".key")
}

// tlsFromMarker turns the persisted flag into a row. The paths come from the
// manager, not from the marker; the certificate's expiry comes from the file
// itself, because "the marker says TLS" and "the certificate is readable" are
// two different claims.
func (m *Manager) tlsFromMarker(p markerPayload) *TLSInfo {
	if p.TLS == nil || !p.TLS.Enabled {
		return nil
	}
	certPath, keyPath := m.certPaths(p.Name)
	t := &TLSInfo{
		Enabled: true, Redirect: p.TLS.Redirect, SelfSigned: p.TLS.SelfSigned, ACME: p.TLS.ACME,
		CertPath: certPath, KeyPath: keyPath,
	}
	leaf, err := readLeaf(certPath)
	if err != nil {
		t.Error = "证书文件不可读：" + err.Error()
		return t
	}
	t.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	return t
}

func readLeaf(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("不是 PEM 证书")
	}
	return x509.ParseCertificate(block.Bytes)
}

// SetSelfSigned creates a one-year ECDSA P-256 certificate carrying every site
// domain as a SAN, then applies it through the same test/reload/rollback path
// as an uploaded certificate. A self-signed certificate is honest about being
// untrusted; it is not a substitute for ACME and the capability bitmap says so.
func (m *Manager) SetSelfSigned(name string, redirect bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	certPEM, keyPEM, err := generateSelfSigned(site.Domains, m.now())
	if err != nil {
		return Site{}, fmt.Errorf("生成自签证书: %w", err)
	}
	return m.setTLS(site, certPEM, keyPEM, redirect, true, false)
}

// SetCertificate applies an operator-supplied certificate chain and key. The
// pair must match and cover every domain the site claims; accepting a
// certificate that nginx will serve for the wrong names is the exact failure
// this check exists to prevent.
func (m *Manager) SetCertificate(name, certPEM, keyPEM string, redirect bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return Site{}, fmt.Errorf("%w：证书与私钥都不能为空", ErrTLSInvalid)
	}
	return m.setTLS(site, []byte(certPEM+"\n"), []byte(keyPEM+"\n"), redirect, false, false)
}

// SetACMECertificate installs a certificate obtained by the ACME issuer. It uses
// the same validation, test, reload and rollback path as an uploaded
// certificate; only the marker's source bit differs, which is what lets the
// renewal loop find certificates it is allowed to replace automatically.
func (m *Manager) SetACMECertificate(name, certPEM, keyPEM string, redirect bool) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return Site{}, fmt.Errorf("%w：CA 返回的证书与私钥不能为空", ErrTLSInvalid)
	}
	return m.setTLS(site, []byte(certPEM+"\n"), []byte(keyPEM+"\n"), redirect, false, true)
}

// ClearCertificate returns the site to plain HTTP. The certificate files are
// removed only after nginx accepted the new configuration; a failed reload
// restores the old vhost and leaves the files intact.
func (m *Manager) ClearCertificate(name string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if site.TLS == nil {
		return site, nil
	}
	prev, err := os.ReadFile(site.ConfigPath)
	if err != nil {
		return Site{}, fmt.Errorf("读取站点配置: %w", err)
	}
	site.TLS = nil
	if err := m.writeConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, fmt.Errorf("写入站点配置: %w", err)
	}
	restore := func() { _ = m.writeConfig(site.ConfigPath, string(prev)) }
	if out, err := m.TestConfig(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：reload 失败：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	m.removeCerts(name)
	return site, nil
}

func (m *Manager) setTLS(site Site, certPEM, keyPEM []byte, redirect, selfSigned, acmeIssued bool) (Site, error) {
	leaf, err := validateCertificate(certPEM, keyPEM, site.Domains, m.now())
	if err != nil {
		return Site{}, err
	}
	certPath, keyPath := m.certPaths(site.Name)
	prevConf, err := os.ReadFile(site.ConfigPath)
	if err != nil {
		return Site{}, fmt.Errorf("读取站点配置: %w", err)
	}
	prevCert, hadCert := readMaybe(certPath)
	prevKey, hadKey := readMaybe(keyPath)

	if err := os.MkdirAll(m.CertDir, 0o700); err != nil {
		return Site{}, fmt.Errorf("创建证书目录: %w", err)
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return Site{}, fmt.Errorf("写入证书: %w", err)
	}
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		restoreFile(certPath, prevCert, hadCert, 0o644)
		return Site{}, fmt.Errorf("写入私钥: %w", err)
	}

	site.TLS = &TLSInfo{
		Enabled: true, Redirect: redirect, SelfSigned: selfSigned, ACME: acmeIssued,
		CertPath: certPath, KeyPath: keyPath,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	if err := m.writeConfig(site.ConfigPath, render(site)); err != nil {
		restoreFile(certPath, prevCert, hadCert, 0o644)
		restoreFile(keyPath, prevKey, hadKey, 0o600)
		return Site{}, fmt.Errorf("写入站点配置: %w", err)
	}
	restore := func() {
		_ = m.writeConfig(site.ConfigPath, string(prevConf))
		restoreFile(certPath, prevCert, hadCert, 0o644)
		restoreFile(keyPath, prevKey, hadKey, 0o600)
	}
	if out, err := m.TestConfig(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：reload 失败：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	return site, nil
}

func (m *Manager) writeConfig(path, body string) error {
	// The TLS paths write vhosts outside applyFiles; they name the same
	// per-site log files, so the log directory needs the same guarantee.
	if err := m.ensureLogDir(); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func readMaybe(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	return b, err == nil
}

func restoreFile(path string, prev []byte, existed bool, mode os.FileMode) {
	if existed {
		_ = writeAtomic(path, prev, mode)
		return
	}
	_ = os.Remove(path)
}

func (m *Manager) removeCerts(name string) {
	certPath, keyPath := m.certPaths(name)
	_ = os.Remove(certPath)
	_ = os.Remove(keyPath)
	_ = os.Remove(m.CertDir) // only removes an empty directory
}

func validateCertificate(certPEM, keyPEM []byte, domains []string, now time.Time) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w：证书与私钥不匹配，或 PEM 无法解析", ErrTLSInvalid)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("%w：证书链为空", ErrTLSInvalid)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%w：无法解析叶子证书", ErrTLSInvalid)
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("%w：证书还未生效（NotBefore=%s）", ErrTLSInvalid, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("%w：证书已过期（NotAfter=%s）", ErrTLSInvalid, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			if !containsDNSName(leaf.DNSNames, d) {
				return nil, fmt.Errorf("%w：证书 SAN 里没有 %s", ErrTLSInvalid, d)
			}
			continue
		}
		if err := leaf.VerifyHostname(d); err != nil {
			return nil, fmt.Errorf("%w：证书不覆盖域名 %s", ErrTLSInvalid, d)
		}
	}
	return leaf, nil
}

func containsDNSName(names []string, want string) bool {
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}

func generateSelfSigned(domains []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	cn := domains[0]
	if len(cn) > 64 {
		cn = cn[:64]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), domains...),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// renderRedirect is the port-80 block used when "force HTTPS" is on. It carries
// no marker: the marker lives in the 443 block, and readSite scans the whole
// file for it.
//
// The ACME challenge location is deliberately before the catch-all redirect.
// A certificate that is renewed every 60 days needs port 80 to answer HTTP-01
// for a few seconds each time; redirecting that path would make the first
// successful issuance unrenewable, which is the kind of "HTTPS is on" state that
// quietly expires ninety days later.
func renderRedirect(s Site) string {
	var b strings.Builder
	b.WriteString("server {\n")
	b.WriteString("    listen 80;\n")
	b.WriteString("    server_name " + strings.Join(s.Domains, " ") + ";\n\n")
	b.WriteString("    root " + s.Root + ";\n")
	if s.LogDir != "" {
		// The redirect block answers every plain-HTTP request when force
		// HTTPS is on; without its own log lines those requests would leave
		// no per-site trace at all.
		b.WriteString("\n" + siteLogLines(s.LogDir, s.Name))
	}
	b.WriteString("\n    location ^~ /.well-known/acme-challenge/ {\n")
	b.WriteString("        default_type text/plain;\n")
	b.WriteString("        try_files $uri =404;\n")
	b.WriteString("    }\n\n")
	b.WriteString("    location / {\n")
	b.WriteString("        return 301 https://$host$request_uri;\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func renderServer(s Site, tlsOn bool) string {
	var b strings.Builder
	b.WriteString("server {\n")
	if tlsOn {
		b.WriteString("    listen 443 ssl;\n")
		if s.TLS != nil && !s.TLS.Redirect {
			b.WriteString("    listen 80;\n")
		}
	} else {
		b.WriteString("    listen 80;\n")
	}
	b.WriteString("    server_name " + strings.Join(s.Domains, " ") + ";\n\n")
	b.WriteString("    root " + s.Root + ";\n")
	switch {
	case len(s.Index) > 0:
		// An explicit list is rendered in the operator's order. A .php entry can
		// only get here when PHP is bound (validateIndex), so nginx will hand it
		// to the handler below instead of serving source text.
		b.WriteString("    index " + strings.Join(s.Index, " ") + ";\n")
	case s.PHPVersion != "":
		// index.php first: a directory that has both index.php and index.html is
		// a PHP application, and serving the static file would silently skip the
		// handler the operator just selected.
		b.WriteString("    index index.php index.html index.htm;\n")
	default:
		b.WriteString("    index index.html index.htm;\n")
	}
	if s.AutoIndex {
		// Server-level directory listing. It is a fixed directive with no
		// arguments the caller controls: when on, a request that resolves to a
		// directory with no default document gets nginx's listing instead of a
		// 403/404. It does not own `location /`, so it coexists with every other
		// site feature.
		b.WriteString("    autoindex on;\n")
	}
	if s.LogDir != "" {
		// Per-site logs. The paths are derived host state, never marker data;
		// ensureLogDir has made the directory worker-writable before this
		// config is ever tested or reloaded.
		b.WriteString("\n" + siteLogLines(s.LogDir, s.Name))
	}
	if tlsOn {
		b.WriteString("\n    ssl_certificate " + s.TLS.CertPath + ";\n")
		b.WriteString("    ssl_certificate_key " + s.TLS.KeyPath + ";\n")
		b.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
		b.WriteString("    ssl_session_cache shared:SSL:10m;\n")
	}
	if len(s.RealIPFrom) > 0 {
		// Server-level real-IP resolution. It only trusts peers the operator
		// listed; the header is one of two fixed names chosen by the writer.
		b.WriteString("\n" + realIPLines(s))
	}
	if s.AuthUser != "" {
		// Server-level Basic Auth. When TLS is on, the HTTP-01 challenge path is
		// exempted: the issuer validates over port 80 without credentials, and a
		// protected challenge directory would silently stop renewals.
		b.WriteString("\n" + authLines(s))
		if tlsOn {
			b.WriteString("\n" + acmeExemptLocation())
		}
	}
	if s.Limits != nil {
		// Server-level traffic limits. They reference zones the panel defines
		// in its own http-level table file, written in the same transaction,
		// and they do not own `location /`, so they coexist with every other
		// site feature.
		b.WriteString("\n" + trafficLimitLines(s.Name, *s.Limits))
	}
	if len(s.RedirectPaths) > 0 {
		// Exact path exceptions render before `location /`. They do not own the
		// catch-all, so they can coexist with the site's static, proxy, rewrite
		// or site-wide redirect behavior.
		b.WriteString("\n" + redirectPathLocations(s.RedirectPaths))
	}
	b.WriteString("\n    location / {\n")
	switch {
	case s.RedirectTarget != "":
		b.WriteString(redirectLocationBody(s))
	case s.ProxyTarget != "":
		b.WriteString(proxyLocationBody(s))
	default:
		b.WriteString("        " + rewriteLocation(s) + "\n")
	}
	b.WriteString("    }\n")
	if s.Hotlink {
		b.WriteString("\n")
		b.WriteString(hotlinkLocationBody(s))
	}
	if s.PHPVersion != "" {
		// try_files keeps a missing script from reaching php-fpm as a request
		// whose SCRIPT_FILENAME points at a file that does not exist. fastcgi_params
		// is the distribution's standard file; SCRIPT_FILENAME is added explicitly
		// because Debian's copy does not contain it.
		b.WriteString("\n    location ~ \\.php$ {\n")
		b.WriteString("        try_files $uri =404;\n")
		b.WriteString("        include fastcgi_params;\n")
		b.WriteString("        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n")
		b.WriteString("        fastcgi_pass unix:" + s.PHPSocket + ";\n")
		b.WriteString("    }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// Get returns one panel-owned site. The ACME layer needs the domains and the
// document root before it can write a challenge; duplicating marker parsing
// there would be a second reader of the same file format.
func (m *Manager) Get(name string) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	return site, nil
}

// PrepareACME makes sure a site that redirects port 80 to 443 currently has the
// challenge exemption in its port-80 block. Configs written by the previous
// slice did not have it, and a certificate obtained before that change would
// otherwise be impossible to renew. The rewrite goes through the same
// test-before-reload protocol as every other config change.
func (m *Manager) PrepareACME(name string) (Site, error) {
	site, err := m.Get(name)
	if err != nil {
		return Site{}, err
	}
	if site.TLS == nil || !site.TLS.Redirect {
		return site, nil
	}
	want := render(site)
	prev, err := os.ReadFile(site.ConfigPath)
	if err != nil {
		return Site{}, fmt.Errorf("读取站点配置: %w", err)
	}
	if string(prev) == want {
		return site, nil
	}
	if err := m.writeConfig(site.ConfigPath, want); err != nil {
		return Site{}, fmt.Errorf("写入站点配置: %w", err)
	}
	restore := func() { _ = m.writeConfig(site.ConfigPath, string(prev)) }
	if out, err := m.TestConfig(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	if out, err := m.Reload(); err != nil {
		restore()
		return Site{}, fmt.Errorf("%w：reload 失败：%v", ErrConfigRejected, strings.TrimSpace(string(out)))
	}
	return site, nil
}
