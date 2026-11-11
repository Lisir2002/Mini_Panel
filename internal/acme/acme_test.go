package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomainsRejectsWildcardAndDuplicates(t *testing.T) {
	if _, err := normalizeDomains([]string{"*.example.com"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("wildcard err = %v, want ErrUnsupported", err)
	}
	got, err := normalizeDomains([]string{"Blog.Example.COM", "blog.example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if strings.Join(got, ",") != "blog.example.com,www.example.com" {
		t.Fatalf("normalized = %v", got)
	}
}

func TestRenewalDueWindow(t *testing.T) {
	now := time.Date(2026, 11, 11, 6, 0, 0, 0, time.UTC)
	cases := []struct {
		notAfter string
		want     bool
	}{
		{now.Add(31 * 24 * time.Hour).Format(time.RFC3339), false},
		{now.Add(30 * 24 * time.Hour).Format(time.RFC3339), true},
		{now.Add(29 * 24 * time.Hour).Format(time.RFC3339), true},
		{now.Add(-time.Hour).Format(time.RFC3339), true},
		{"not-a-date", true},
	}
	for _, c := range cases {
		if got := RenewalDue(c.notAfter, now); got != c.want {
			t.Errorf("RenewalDue(%q) = %v, want %v", c.notAfter, got, c.want)
		}
	}
}

func TestAccountKeyIsCreatedOnceWithOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme", "account.key")
	k1, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("account key mode = %o, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("account dir mode = %v, err=%v; want 0700", fiMode(fi), err)
	}
	k2, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("reload account key: %v", err)
	}
	if k1.Public().(*ecdsa.PublicKey).X.Cmp(k2.Public().(*ecdsa.PublicKey).X) != 0 {
		t.Error("reloading the account key generated a different key")
	}
}

func TestChallengeFileIsServedAndRemoved(t *testing.T) {
	root := t.TempDir()
	path, err := writeChallenge(root, "token-123_abc", "token-123_abc.key-auth")
	if err != nil {
		t.Fatalf("write challenge: %v", err)
	}
	if want := filepath.Join(root, ".well-known", "acme-challenge", "token-123_abc"); path != want {
		t.Errorf("challenge path = %s, want %s", path, want)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "token-123_abc.key-auth" {
		t.Fatalf("challenge body = %q, err=%v", b, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("challenge file mode = %o, want 0644", fi.Mode().Perm())
	}
	removeChallenge(path)
	for _, p := range []string{path, filepath.Dir(path), filepath.Join(root, ".well-known")} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists after cleanup", p)
		}
	}
}

func TestChallengeRejectsSymlinkedWellKnown(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".well-known")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeChallenge(root, "token", "body"); err == nil {
		t.Fatal("symlinked .well-known was followed")
	}
	if _, err := os.Stat(filepath.Join(outside, "acme-challenge", "token")); !errors.Is(err, os.ErrNotExist) {
		t.Error("challenge escaped the site root")
	}
}

func TestIssueRejectsWildcardBeforeNetwork(t *testing.T) {
	iss := &Issuer{DirectoryURL: "http://127.0.0.1:1/dir", AccountKeyPath: filepath.Join(t.TempDir(), "account.key")}
	root := t.TempDir()
	if _, err := iss.Issue(t.Context(), []string{"*.example.com"}, root); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Issue wildcard err = %v, want ErrUnsupported", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".well-known")); !errors.Is(err, os.ErrNotExist) {
		t.Error("wildcard attempt wrote a challenge directory")
	}
}

func TestIssueRequiresExistingWebroot(t *testing.T) {
	iss := &Issuer{DirectoryURL: "http://127.0.0.1:1/dir", AccountKeyPath: filepath.Join(t.TempDir(), "account.key")}
	if _, err := iss.Issue(t.Context(), []string{"example.com"}, filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrFailed) {
		t.Fatalf("missing webroot err = %v, want ErrFailed", err)
	}
}

func TestParseAccountKeyAcceptsECPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseAccountKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("parse EC key: %v", err)
	}
	if got.Public().(*ecdsa.PublicKey).X.Cmp(key.X) != 0 {
		t.Error("parsed key differs")
	}
}

func TestCSRCoversEveryDomain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	domains := []string{"blog.example.com", "www.example.com"}
	der, err := makeCSR(key, domains)
	if err != nil {
		t.Fatalf("makeCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if strings.Join(csr.DNSNames, ",") != strings.Join(domains, ",") {
		t.Errorf("CSR DNSNames = %v", csr.DNSNames)
	}
}

func fiMode(fi os.FileInfo) os.FileMode {
	if fi == nil {
		return 0
	}
	return fi.Mode().Perm()
}
