package sec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
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
