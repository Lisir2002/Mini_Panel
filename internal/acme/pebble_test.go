package acme

// This test runs the real issuer against Pebble, the ACME test server Let's
// Encrypt publishes. It is skipped when no `pebble` binary is available, so the
// normal unit suite stays hermetic; the release checklist runs it explicitly:
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.8.0
//	PATH="$(go env GOPATH)/bin:$PATH" go test ./internal/acme -run Pebble -v
//
// Nothing here is mocked: order creation, HTTP-01 token serving, authorization
// polling, CSR finalize and chain download all go through the same code path a
// Let's Encrypt production request uses.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPebbleHTTP01Issuance(t *testing.T) {
	pebble, err := exec.LookPath("pebble")
	if err != nil {
		if p := os.Getenv("PEBBLE_BIN"); p != "" {
			pebble = p
		} else {
			t.Skip("pebble 不存在；按 pebble_test.go 顶部命令安装后重跑")
		}
	}
	dir := t.TempDir()
	caPEM, caKey, caCert := testCA(t)
	serverCert, serverKey := testServerCert(t, caCert, caKey)
	certPath := filepath.Join(dir, "pebble.crt")
	keyPath := filepath.Join(dir, "pebble.key")
	writePEM(t, certPath, "CERTIFICATE", serverCert)
	writePEM(t, keyPath, "EC PRIVATE KEY", serverKey)

	acmePort, mgmtPort := freePort(t), freePort(t)
	challengePort := freePort(t)
	cfg := map[string]any{"pebble": map[string]any{
		"listenAddress":                  "127.0.0.1:" + acmePort,
		"managementListenAddress":        "127.0.0.1:" + mgmtPort,
		"certificate":                    certPath,
		"privateKey":                     keyPath,
		"httpPort":                       atoiPort(t, challengePort),
		"tlsPort":                        atoiPort(t, freePort(t)),
		"externalAccountBindingRequired": false,
	}}
	cfgPath := filepath.Join(dir, "pebble.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, pebble, "-config", cfgPath, "-strict=false")
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pebble: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("pebble log:\n%s", logs.String())
		}
	}()

	webroot := filepath.Join(dir, "webroot")
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", ":"+challengePort)
	if err != nil {
		t.Fatalf("listen challenge: %v", err)
	}
	httpSrv := &http.Server{Handler: http.FileServer(http.Dir(webroot))}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append test CA")
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		Timeout:   20 * time.Second,
	}
	directoryURL := "https://127.0.0.1:" + acmePort + "/dir"
	waitForDirectory(t, client, directoryURL, 15*time.Second, &logs)

	iss := &Issuer{
		DirectoryURL:   directoryURL,
		AccountKeyPath: filepath.Join(dir, "account.key"),
		HTTPClient:     client,
		Timeout:        60 * time.Second,
	}
	creds, err := iss.Issue(context.Background(), []string{"localhost"}, webroot)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(creds.CertPEM) == 0 || len(creds.KeyPEM) == 0 {
		t.Fatal("empty credentials returned")
	}
	if _, err := tls.X509KeyPair(creds.CertPEM, creds.KeyPEM); err != nil {
		t.Fatalf("returned pair does not match: %v", err)
	}
	block, _ := pem.Decode(creds.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("issued cert does not cover localhost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(webroot, ".well-known", "acme-challenge")); !os.IsNotExist(err) {
		t.Errorf("challenge directory left behind: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "account.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("account key mode = %v, err=%v; want 0600", fiMode(fi), err)
	}

	// The second issuance is the renewal path after a process restart: the
	// account key already exists and the CA answers ErrAccountAlreadyExists.
	// Treating that as fatal made the first automatic renewal fail, so it is
	// exercised here rather than only in a unit test.
	creds2, err := iss.Issue(context.Background(), []string{"localhost"}, webroot)
	if err != nil {
		t.Fatalf("second Issue (existing account): %v", err)
	}
	if len(creds2.CertPEM) == 0 {
		t.Fatal("second issuance returned an empty certificate")
	}
	if _, err := tls.X509KeyPair(creds2.CertPEM, creds2.KeyPEM); err != nil {
		t.Fatalf("second returned pair does not match: %v", err)
	}
}

func waitForDirectory(t *testing.T, c *http.Client, url string, timeout time.Duration, logs *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res, err := c.Get(url)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("pebble directory %s did not become ready\n%s", url, logs.String())
}

func testCA(t *testing.T) (certPEM []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Mini Panel test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, cert
}

func testServerCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "pebble"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		DNSNames: []string{"localhost", "pebble"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return der, keyDER
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func atoiPort(t *testing.T, s string) int {
	t.Helper()
	var p int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &p); err != nil {
		t.Fatal(err)
	}
	return p
}
