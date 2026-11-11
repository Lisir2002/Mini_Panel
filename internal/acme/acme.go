// Package acme issues and renews site certificates through RFC 8555 HTTP-01.
//
// It deliberately implements one challenge type and one flow: the panel already
// owns the site's document root and the nginx vhost on port 80, so writing a
// token file there and asking the CA to fetch it is the smallest honest
// implementation. DNS-01 is what wildcard certificates need, and this package
// refuses wildcards instead of pretending a DNS provider exists.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// DefaultDirectoryURL is Let's Encrypt production. The environment override in
// the platform layer exists for private CAs and for the Pebble integration test;
// an operator pointing the panel at staging is making an explicit choice, not
// getting a silent downgrade.
const DefaultDirectoryURL = xacme.LetsEncryptURL

// RenewBefore is the window in which automatic renewal runs. Let's Encrypt
// certificates live 90 days, so thirty days leaves plenty of retries for a DNS
// or port-80 outage without reissuing on every scheduler tick.
const RenewBefore = 30 * 24 * time.Hour

var (
	// ErrUnsupported means the requested name cannot be proven with HTTP-01.
	// Wildcards are the only current case: they require DNS-01.
	ErrUnsupported = errors.New("ACME HTTP-01 不支持该域名")
	// ErrFailed is any failed step after the request was accepted: account
	// registration, order, challenge validation, finalize, or certificate
	// download. The wrapped text is safe to show to the operator.
	ErrFailed = errors.New("ACME 签发失败")
)

// Credentials is the issued chain and the matching private key, both PEM. The
// key is generated per certificate instead of being reused from the account key:
// one compromised certificate key must not put every site on the host at risk.
type Credentials struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Issuer is one ACME account and directory. It holds no mutable account state in
// memory beyond the x/crypto client cache; the account key is the durable fact.
type Issuer struct {
	DirectoryURL   string
	AccountKeyPath string
	HTTPClient     *http.Client
	Timeout        time.Duration
}

// NewIssuer builds an issuer with the default HTTP client, optionally trusting
// an extra CA file. The CA file is for a private ACME directory (and for tests);
// production Let's Encrypt uses the system roots.
func NewIssuer(directory, accountKeyPath, caFile string) (*Issuer, error) {
	if strings.TrimSpace(directory) == "" {
		directory = DefaultDirectoryURL
	}
	if strings.TrimSpace(accountKeyPath) == "" {
		return nil, errors.New("ACME 账户密钥路径为空")
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("默认 HTTP Transport 不可用")
	}
	clone := tr.Clone()
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("读取 ACME CA 证书: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("ACME CA 文件 %s 里没有可用证书", caFile)
		}
		clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &Issuer{
		DirectoryURL:   directory,
		AccountKeyPath: accountKeyPath,
		HTTPClient:     &http.Client{Transport: clone, Timeout: 60 * time.Second},
		Timeout:        5 * time.Minute,
	}, nil
}

// RenewalDue answers whether a certificate with this NotAfter value should be
// renewed. An unreadable timestamp is treated as due: the safe response to "I do
// not know when this expires" is to try to replace it, not to wait.
func RenewalDue(notAfter string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return true
	}
	return !t.After(now.Add(RenewBefore))
}

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// Issue obtains one certificate for domains using an HTTP-01 challenge served
// from webroot. The challenge file exists only while the CA is validating it;
// every return path removes it. A wildcard anywhere in the list fails before any
// network call.
func (i *Issuer) Issue(ctx context.Context, domains []string, webroot string) (Credentials, error) {
	clean, err := normalizeDomains(domains)
	if err != nil {
		return Credentials{}, err
	}
	if strings.TrimSpace(webroot) == "" {
		return Credentials{}, fmt.Errorf("%w：站点根目录为空，HTTP-01 没有可写位置", ErrFailed)
	}
	if st, err := os.Stat(webroot); err != nil || !st.IsDir() {
		return Credentials{}, fmt.Errorf("%w：站点根目录 %s 不存在或不是目录", ErrFailed, webroot)
	}
	accountKey, err := loadOrCreateAccountKey(i.AccountKeyPath)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：准备 ACME 账户密钥：%v", ErrFailed, err)
	}

	timeout := i.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &xacme.Client{
		Key:          accountKey,
		DirectoryURL: i.DirectoryURL,
		HTTPClient:   i.HTTPClient,
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil &&
		!errors.Is(err, xacme.ErrAccountAlreadyExists) {
		// The key is persisted, so every renewal runs on an account the CA
		// already knows. Register reporting that fact is success, not a reason
		// to refuse the first automatic renewal after a restart.
		return Credentials{}, fmt.Errorf("%w：注册/读取 ACME 账户：%v", ErrFailed, err)
	}

	ids := make([]xacme.AuthzID, 0, len(clean))
	for _, d := range clean {
		ids = append(ids, xacme.AuthzID{Type: "dns", Value: d})
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：创建订单：%v", ErrFailed, err)
	}

	var challengeFiles []string
	defer func() {
		for _, p := range challengeFiles {
			removeChallenge(p)
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return Credentials{}, fmt.Errorf("%w：读取授权 %s：%v", ErrFailed, authzURL, err)
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		if authz.Wildcard {
			return Credentials{}, fmt.Errorf("%w：%s 的授权是通配符，需要 DNS-01", ErrUnsupported, authz.Identifier.Value)
		}
		chal := httpChallenge(authz)
		if chal == nil {
			return Credentials{}, fmt.Errorf("%w：%s 没有可用的 HTTP-01 挑战", ErrFailed, authz.Identifier.Value)
		}
		response, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return Credentials{}, fmt.Errorf("%w：生成挑战响应：%v", ErrFailed, err)
		}
		path, err := writeChallenge(webroot, chal.Token, response)
		if err != nil {
			return Credentials{}, fmt.Errorf("%w：写入 HTTP-01 挑战文件：%v", ErrFailed, err)
		}
		challengeFiles = append(challengeFiles, path)
		if _, err := client.Accept(ctx, chal); err != nil {
			return Credentials{}, fmt.Errorf("%w：提交挑战：%v", ErrFailed, err)
		}
		if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
			return Credentials{}, fmt.Errorf("%w：CA 未通过 %s 的验证：%v", ErrFailed, authz.Identifier.Value, err)
		}
		removeChallenge(path)
	}

	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：等待订单就绪：%v", ErrFailed, err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：生成证书私钥：%v", ErrFailed, err)
	}
	csr, err := makeCSR(certKey, clean)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：生成 CSR：%v", ErrFailed, err)
	}
	chain, _, err := client.CreateCertFromOrder(ctx, ready, csr, true)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：签发证书：%v", ErrFailed, err)
	}
	if len(chain) == 0 {
		return Credentials{}, fmt.Errorf("%w：CA 返回了空证书链", ErrFailed)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return Credentials{}, fmt.Errorf("%w：编码证书私钥：%v", ErrFailed, err)
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return Credentials{
		CertPEM: certPEM,
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

func normalizeDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("%w：站点没有域名", ErrFailed)
	}
	out := make([]string, 0, len(domains))
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			return nil, fmt.Errorf("%w：域名列表里有空值", ErrFailed)
		}
		if strings.HasPrefix(d, "*.") {
			return nil, fmt.Errorf("%w：%s 是通配符，HTTP-01 不能验证；请改用上传证书或 DNS-01（尚未交付）", ErrUnsupported, d)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

func httpChallenge(a *xacme.Authorization) *xacme.Challenge {
	for _, c := range a.Challenges {
		if c.Type == "http-01" && (c.Status == xacme.StatusPending || c.Status == xacme.StatusProcessing || c.Status == "") {
			return c
		}
	}
	return nil
}

func makeCSR(key crypto.Signer, domains []string) ([]byte, error) {
	cn := domains[0]
	if len(cn) > 64 {
		cn = cn[:64]
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: append([]string(nil), domains...),
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		// Repair a key copied with a loose mode instead of using it silently.
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return parseAccountKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func parseAccountKey(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("账户密钥不是 PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := k.(type) {
		case *ecdsa.PrivateKey:
			return key, nil
		case *rsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("账户密钥类型 %T 不支持", k)
		}
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("无法解析 ACME 账户密钥")
}

// writeChallenge writes token under webroot/.well-known/acme-challenge. The
// token comes from the CA and is used as a filename, so it is validated before
// it reaches filepath.Join. The directory is created 0755 (nginx must be able to
// read it), the token 0644, and neither existing symlink is followed.
func writeChallenge(webroot, token, body string) (string, error) {
	if !tokenRe.MatchString(token) {
		return "", errors.New("ACME 挑战 token 形状不合法")
	}
	base := filepath.Join(webroot, ".well-known")
	dir := filepath.Join(base, "acme-challenge")
	for _, p := range []string{base, dir} {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return "", err
		case fi.Mode()&os.ModeSymlink != 0:
			return "", fmt.Errorf("%s 是符号链接，拒绝把挑战写到链接目标", p)
		case !fi.IsDir():
			return "", fmt.Errorf("%s 不是目录", p)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, token)
	if err := writeFileAtomic(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func removeChallenge(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
	_ = os.Remove(filepath.Dir(path))               // acme-challenge, only if empty
	_ = os.Remove(filepath.Dir(filepath.Dir(path))) // .well-known, only if empty
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
