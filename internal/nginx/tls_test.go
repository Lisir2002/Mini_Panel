package nginx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedTLSRendersAndLists(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com", "www.blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetSelfSigned("blog", true)
	if err != nil {
		t.Fatalf("SetSelfSigned: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}
	if site.TLS == nil || !site.TLS.Enabled || !site.TLS.Redirect || !site.TLS.SelfSigned {
		t.Fatalf("TLS row = %+v", site.TLS)
	}
	if site.TLS.NotAfter == "" {
		t.Error("NotAfter is empty")
	}
	certPath, keyPath := m.certPaths("blog")
	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, err=%v; want 0600", fiMode(fi), err)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"listen 443 ssl;",
		"return 301 https://$host$request_uri;",
		"ssl_certificate " + certPath + ";",
		"ssl_certificate_key " + keyPath + ";",
		"ssl_protocols TLSv1.2 TLSv1.3;",
		markerLine,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("config missing %q\n%s", want, body)
		}
	}
	leaf, err := readLeaf(certPath)
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	for _, d := range []string{"blog.example.com", "www.blog.example.com"} {
		if err := leaf.VerifyHostname(d); err != nil {
			t.Errorf("generated cert does not cover %s: %v", d, err)
		}
	}
	list, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].TLS == nil || !list[0].TLS.Enabled || list[0].TLS.Error != "" {
		t.Errorf("List TLS = %+v", list)
	}
}

func fiMode(fi os.FileInfo) os.FileMode {
	if fi == nil {
		return 0
	}
	return fi.Mode().Perm()
}

func TestUploadedCertificateMustCoverSiteDomains(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC)
	certPEM, keyPEM := testCert(t, []string{"other.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := m.SetCertificate("blog", string(certPEM), string(keyPEM), false); !errors.Is(err, ErrTLSInvalid) {
		t.Fatalf("wrong-domain cert err = %v, want ErrTLSInvalid", err)
	}
	if body, _ := os.ReadFile(m.Layout.ConfigPath("blog")); strings.Contains(string(body), "ssl_certificate") {
		t.Error("rejected certificate still changed the vhost")
	}
	if _, err := os.Stat(filepath.Join(m.CertDir, "blog.crt")); !errors.Is(err, os.ErrNotExist) {
		t.Error("rejected certificate left a file behind")
	}

	goodCert, goodKey := testCert(t, []string{"blog.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	site, err := m.SetCertificate("blog", string(goodCert), string(goodKey), false)
	if err != nil {
		t.Fatalf("SetCertificate: %v", err)
	}
	if site.TLS == nil || site.TLS.SelfSigned || site.TLS.Redirect {
		t.Errorf("uploaded TLS row = %+v", site.TLS)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if !strings.Contains(string(body), "listen 443 ssl;") || !strings.Contains(string(body), "listen 80;") {
		t.Errorf("non-redirect TLS config should listen on both ports\n%s", body)
	}
	if strings.Contains(string(body), "return 301") {
		t.Error("non-redirect TLS config contains a redirect")
	}
}

func TestTLSRollbackOnConfigTestFailure(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetSelfSigned("blog", true); err != nil {
		t.Fatalf("first SetSelfSigned: %v", err)
	}
	beforeConf, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	certPath, keyPath := m.certPaths("blog")
	beforeCert, _ := os.ReadFile(certPath)
	beforeKey, _ := os.ReadFile(keyPath)

	rec.cmds = nil
	rec.failOn = "-t"
	if _, err := m.SetSelfSigned("blog", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	if got, _ := os.ReadFile(m.Layout.ConfigPath("blog")); string(got) != string(beforeConf) {
		t.Error("vhost was not restored after a failed nginx -t")
	}
	if got, _ := os.ReadFile(certPath); string(got) != string(beforeCert) {
		t.Error("certificate was not restored after a failed nginx -t")
	}
	if got, _ := os.ReadFile(keyPath); string(got) != string(beforeKey) {
		t.Error("private key was not restored after a failed nginx -t")
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].TLS == nil || !list[0].TLS.Redirect {
		t.Errorf("previous TLS state not visible after rollback: %+v", list)
	}
	if len(rec.cmds) != 1 || rec.cmds[0] != "nginx -t" {
		t.Errorf("commands = %v, want only the failing test", rec.cmds)
	}
}

func TestTLSRollbackOnReloadFailure(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetSelfSigned("blog", true); err != nil {
		t.Fatalf("first SetSelfSigned: %v", err)
	}
	beforeConf, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	certPath, _ := m.certPaths("blog")
	beforeCert, _ := os.ReadFile(certPath)
	rec.failOn = "reload"
	if _, err := m.SetSelfSigned("blog", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	if got, _ := os.ReadFile(m.Layout.ConfigPath("blog")); string(got) != string(beforeConf) {
		t.Error("vhost was not restored after a failed reload")
	}
	if got, _ := os.ReadFile(certPath); string(got) != string(beforeCert) {
		t.Error("certificate was not restored after a failed reload")
	}
}

func TestClearTLSRemovesCertificateFiles(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetSelfSigned("blog", true); err != nil {
		t.Fatalf("SetSelfSigned: %v", err)
	}
	rec.cmds = nil
	site, err := m.ClearCertificate("blog")
	if err != nil {
		t.Fatalf("ClearCertificate: %v", err)
	}
	if site.TLS != nil {
		t.Errorf("TLS still reported after clear: %+v", site.TLS)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %v, want %v", rec.cmds, want)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if strings.Contains(string(body), "ssl_certificate") || strings.Contains(string(body), "listen 443") {
		t.Errorf("TLS directives left after clear\n%s", body)
	}
	certPath, keyPath := m.certPaths("blog")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind after clear", p)
		}
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].TLS != nil {
		t.Errorf("List after clear = %+v", list)
	}
}

func TestDeleteSiteRemovesManagedCertificate(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetSelfSigned("blog", true); err != nil {
		t.Fatalf("SetSelfSigned: %v", err)
	}
	if _, err := m.Delete("blog"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	certPath, keyPath := m.certPaths("blog")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind after site delete", p)
		}
	}
}

func TestExpiredCertificateIsRejected(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC)
	certPEM, keyPEM := testCert(t, []string{"blog.example.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if _, err := m.SetCertificate("blog", string(certPEM), string(keyPEM), false); !errors.Is(err, ErrTLSInvalid) {
		t.Fatalf("expired cert err = %v, want ErrTLSInvalid", err)
	}
	if body, _ := os.ReadFile(m.Layout.ConfigPath("blog")); strings.Contains(string(body), "ssl_certificate") {
		t.Error("expired certificate still changed the vhost")
	}
}

func testCert(t *testing.T, domains []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domains[0]},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
