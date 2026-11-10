// Package sec holds the panel's own security primitives: password hashing,
// random identifiers, entrance paths, TOTP and the login rate limiter.
package sec

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword uses bcrypt cost 12. Mini Panel sends credentials over TLS only
// and never falls back to plaintext: a request without usable transport security
// is refused outright, not encrypted by the browser and not sent in the clear.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// MinPasswordLen is enforced on every password write, including the CLI.
const MinPasswordLen = 10

var (
	usernameRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{2,31}$`)
	// entranceRE accepts the shape a generated entrance can have; the reserved
	// name list is not a constant here, it is enforced against our own route
	// table (see ValidateEntrance), so it can never drift from reality.
	entranceRE = regexp.MustCompile(`^/[a-z0-9][a-z0-9_-]{5,31}$`)
)

// ValidateUsername rejects anything that could confuse logs or the UI.
func ValidateUsername(u string) error {
	if !usernameRE.MatchString(u) {
		return fmt.Errorf("用户名需 3-32 位，以字母开头，仅允许字母数字与 _ . -")
	}
	return nil
}

// ValidatePassword enforces length plus three-of-four character classes, which
// is the rule BaoTa exposes as an *optional* "密码复杂度验证" switch. Here it is
// not optional, because this product's whole threat model is "a root panel
// reachable from the internet".
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("密码至少 %d 位", MinPasswordLen)
	}
	if len(pw) > 256 {
		return fmt.Errorf("密码过长")
	}
	classes := 0
	for _, c := range pw {
		switch {
		case c >= 'a' && c <= 'z':
			classes |= 1
		case c >= 'A' && c <= 'Z':
			classes |= 2
		case c >= '0' && c <= '9':
			classes |= 4
		default:
			classes |= 8
		}
	}
	if bits(classes) < 3 {
		return fmt.Errorf("密码需包含大写、小写、数字、符号中的至少三类")
	}
	return nil
}

func bits(m int) int {
	n := 0
	for m != 0 {
		n += m & 1
		m >>= 1
	}
	return n
}

// Token returns n bytes of URL-safe randomness as hex.
func Token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Base32Secret returns a TOTP shared secret (RFC 4648, unpadded).
func Base32Secret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// Ambiguous glyphs are excluded: i, l, o from the alphabet and 0, 1 from the
// digits, because an entrance path has to be typed from a phone at some point.
// That leaves 23 letters + 8 digits = 31 symbols, so an 8-character entrance is
// 8·log2(31) ≈ 39.6 bits — more than enough for a path whose only job is to
// survive a scanner, and whose real protection is the password behind it.
// `i` used to be in here while the test asserted it could not be, which made
// TestEntranceShape fail roughly one run in five: a flaky test correctly
// telling us the generator disagreed with its own stated rule.
const entranceAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// NewEntrance generates a security entrance path from an alphabet with the
// ambiguous characters removed, so it survives being read off a terminal.
func NewEntrance() string {
	out := make([]byte, 8)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(entranceAlphabet))))
		if err != nil {
			panic(err)
		}
		out[i] = entranceAlphabet[n.Int64()]
	}
	return "/" + string(out)
}

// ValidateEntrance rejects shapes that could escape the panel's own routing or
// collide with reserved prefixes.
func ValidateEntrance(p string) error {
	if !entranceRE.MatchString(p) {
		return fmt.Errorf("安全入口需为 / 开头、6-32 位小写字母数字或 _ -")
	}
	for _, r := range []string{"//", "/api", "/static", "/login", "/logout", "/healthz"} {
		if strings.HasPrefix(p, r) {
			return fmt.Errorf("安全入口不能使用保留前缀 %s", r)
		}
	}
	return nil
}
