package sec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EnsureSelfSignedTLS provisions the panel's own HTTPS certificate, the same role
// BaoTa's data/ssl.pl + ssl/certificate.pem pair plays. It is regenerated when it
// is missing, when it expires within 30 days, or when the host/IP set changes —
// that last check is what makes "change the server IP and the panel SSL breaks"
// an automatic repair instead of a support ticket.
func EnsureSelfSignedTLS(dir string, hosts []string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "panel-cert.pem")
	keyPath = filepath.Join(dir, "panel-key.pem")

	old, err := os.ReadFile(certPath)
	if err == nil {
		if blk, _ := pem.Decode(old); blk != nil {
			if c, cerr := x509.ParseCertificate(blk.Bytes); cerr == nil {
				if time.Until(c.NotAfter) > 30*24*time.Hour && sameHosts(c.DNSNames, c.IPAddresses, hosts) {
					return certPath, keyPath, nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Mini Panel", Organization: []string{"Mini Panel"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(397 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.IPAddresses) == 0 && len(tmpl.DNSNames) == 0 {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"))
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	cf, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	kf, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", "", err
	}
	defer kf.Close()
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func sameHosts(dns []string, ips []net.IP, want []string) bool {
	got := map[string]bool{}
	for _, d := range dns {
		got[d] = true
	}
	for _, i := range ips {
		got[i.String()] = true
	}
	wanted := map[string]bool{}
	for _, w := range want {
		if w != "" {
			wanted[w] = true
		}
	}
	if len(got) != len(wanted) {
		return false
	}
	for k := range wanted {
		if !got[k] {
			return false
		}
	}
	return true
}

// HostListForCert is a tiny helper kept here so main.go stays readable.
func HostListForCert(hosts []string) []string {
	out := append([]string{}, hosts...)
	sort.Strings(out)
	return out
}

// CertPath is where the panel's own certificate lives inside dir. Both the
// self-check and the lockout table need the same file, so the name is not spelled
// out at two call sites any more than it has to be.
func CertPath(dir string) string { return filepath.Join(dir, "panel-cert.pem") }

// CertInfo is everything the panel can learn about its own certificate from the
// file on disk. It exists because two callers ask different questions about the
// same file — `doctor` wants one human sentence, the lockout table wants "could
// this be why I cannot reach the panel" — and they must not parse it differently.
type CertInfo struct {
	// Summary is the sentence to show: expiry + SANs, or what is wrong instead.
	Summary string
	// Usable is whether a TLS handshake could be served from this file right
	// now: parseable, within its validity window. A self-signed certificate is
	// still "usable" here — the browser warning is a trust question, not a
	// availability one, and the panel must not report a lock-out it does not cause.
	Usable bool
	// Err is non-nil only when the file could not be read at all (permissions,
	// I/O), which is the one case where `doctor` refuses to guess and fails.
	Err error
}

func ReadCert(path string) CertInfo {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return CertInfo{Summary: "尚未生成（启动或 minipanel init 时自动创建）"}
	}
	if err != nil {
		return CertInfo{Summary: "无法读取", Err: err}
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return CertInfo{Summary: "文件存在但无法解析，建议删除后重新 init"}
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return CertInfo{Summary: "解析失败：" + err.Error()}
	}
	now := time.Now()
	usable := now.After(c.NotBefore) && c.NotAfter.After(now)
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	summary := fmt.Sprintf("%s 到期，SAN: %s", c.NotAfter.Format("2006-01-02"), strings.Join(sans, " "))
	if !usable {
		if now.Before(c.NotBefore) {
			return CertInfo{Summary: "有效期未到（" + c.NotBefore.Format("2006-01-02") + "）：" + summary}
		}
		return CertInfo{Summary: "已于 " + c.NotAfter.Format("2006-01-02") + " 过期"}
	}
	return CertInfo{Summary: summary, Usable: true}
}
