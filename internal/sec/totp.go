package sec

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

// RFC 6238 TOTP, implemented directly (HMAC-SHA1, 30 s step, 6 digits) so the
// panel carries no third-party 2FA dependency. BaoTa exposes 2FA as an opt-in
// switch that is off by default on every freshly installed host we inspected
// (data/two_step_auth.txt absent); Mini Panel surfaces it during first setup.

const (
	totpStep   = 30
	totpDigits = 6
	totpSkew   = 1 // accept previous/next window to tolerate clock drift
	totpIssuer = "Mini Panel"
)

// TOTPURL builds the otpauth:// URI shown as a QR code payload.
func TOTPURL(secret, account string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		strings.ReplaceAll(totpIssuer, " ", "%20"),
		strings.ReplaceAll(account, " ", "%20"),
		secret,
		strings.ReplaceAll(totpIssuer, " ", "%20"),
		totpDigits, totpStep)
}

// TOTPCode returns the current code for a secret.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}
	counter := at.Unix() / totpStep
	return hotp(key, counter)
}

// VerifyTOTP accepts a code within ±totpSkew steps of now.
func VerifyTOTP(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	counter := at.Unix() / totpStep
	for d := -int64(totpSkew); d <= int64(totpSkew); d++ {
		want, err := hotp(key, counter+int64(d))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

func hotp(key []byte, counter int64) (string, error) {
	var msg [8]byte
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(msg[:]); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	code := bin % 1000000
	return fmt.Sprintf("%06d", code), nil
}
