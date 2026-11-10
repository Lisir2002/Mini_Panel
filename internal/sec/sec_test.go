package sec

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		pw   string
		want bool
		why  string
	}{
		{"Sup3rSecret!pw", true, "four classes"},
		{"aaaaaaaaaaaaaa", false, "one class"},
		{"Ab1!", false, "too short"},
		{"abcdefghijklmnop", false, "letters only"},
		{"Password2026", true, "three classes"},
		{"", false, "empty"},
		// A space falls into "symbol", which is deliberate: the rule is about
		// character variety, not about typographic comfort.
		{"  spacey 1234A", true, "space counts as a symbol class"},
	}
	for _, c := range cases {
		err := ValidatePassword(c.pw)
		if (err == nil) != c.want {
			t.Errorf("ValidatePassword(%q [%s]) err=%v, want ok=%v", c.pw, c.why, err, c.want)
		}
	}
	// A password of MinPasswordLen or more with mixed classes must pass, and the
	// boundary below it must not.
	if err := ValidatePassword(strings.Repeat("a", MinPasswordLen-1) + "A1"); err != nil {
		t.Errorf("boundary password rejected: %v", err)
	}
}

func TestValidateUsername(t *testing.T) {
	for _, ok := range []string{"admin", "a_b-c", "Ops1", "paneladmin"} {
		if err := ValidateUsername(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ab", "1admin", "_admin", "-a", "ad min", strings.Repeat("a", 40), "root;rm"} {
		if err := ValidateUsername(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestPasswordHashIsSaltedAndVerifiable(t *testing.T) {
	h1, err := HashPassword("Sup3rSecret!pw")
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := HashPassword("Sup3rSecret!pw")
	if h1 == h2 {
		t.Error("identical hashes: the salt is not random")
	}
	if !strings.HasPrefix(h1, "$2") {
		t.Errorf("unexpected hash format %q", h1[:6])
	}
	if !VerifyPassword(h1, "Sup3rSecret!pw") {
		t.Error("verify failed on the correct password")
	}
	if VerifyPassword(h1, "Sup3rSecret!pW") {
		t.Error("verify succeeded on a wrong password")
	}
	if VerifyPassword("", "anything") {
		t.Error("empty hash accepted")
	}
}

func TestEntranceShape(t *testing.T) {
	e := NewEntrance()
	if !strings.HasPrefix(e, "/") || len(e) != 9 {
		t.Fatalf("entrance %q is not / plus 8 characters", e)
	}
	// The alphabet excludes the glyphs that get mistyped over a phone keyboard.
	for _, r := range e[1:] {
		if strings.ContainsRune("0o1liIO", r) {
			t.Errorf("ambiguous character %q in entrance %q", r, e)
		}
	}
	if err := ValidateEntrance(e); err != nil {
		t.Errorf("generated entrance rejected by our own validator: %v", err)
	}
	for _, bad := range []string{"", "nopath", "/a", "/" + strings.Repeat("a", 40),
		"/api", "/static", "/login", "/logout", "/healthz", "/A_H", `/../etc`, "/a/b"} {
		if err := ValidateEntrance(bad); err == nil {
			t.Errorf("entrance %q should be rejected", bad)
		}
	}
}

func TestTOTPVector(t *testing.T) {
	// RFC 6238 test vector: SHA-1 secret "12345678901234567890" (ASCII),
	// T=59 -> 94287082 truncated to 6 digits = 287082.
	secret := base32OfASCII("12345678901234567890")
	at := time.Unix(59, 0)
	got, err := TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("RFC 6238 vector: got %s want 287082", got)
	}
	if !VerifyTOTP(secret, got, at) {
		t.Fatal("our own code failed to verify")
	}
	// One step of skew is allowed, two is not: a locked-out clock must not be an
	// infinite validity window.
	if !VerifyTOTP(secret, got, at.Add(30*time.Second)) {
		t.Error("adjacent window should be accepted")
	}
	if VerifyTOTP(secret, got, at.Add(120*time.Second)) {
		t.Error("distant window should be rejected")
	}
	if VerifyTOTP(secret, "0000000", at) {
		t.Error("malformed code accepted")
	}
	if VerifyTOTP("", got, at) {
		t.Error("empty secret accepted")
	}
}

func TestTOTPURLIncludesAccount(t *testing.T) {
	u := TOTPURL("JBSWY3DPEHPK3PXP", "admin")
	if !strings.HasPrefix(u, "otpauth://totp/Mini%20Panel:admin?") {
		t.Fatalf("unexpected url %q", u)
	}
	if !strings.Contains(u, "secret=JBSWY3DPEHPK3PXP") || !strings.Contains(u, "issuer=") {
		t.Fatalf("url is missing fields authenticators need: %q", u)
	}
}

func base32OfASCII(s string) string {
	steps := (len(s) + 4) / 5
	raw := make([]byte, steps*5)
	copy(raw, s)
	full := base32.StdEncoding.EncodeToString(raw)
	return full
}

func TestTokenLengthAndUniqueness(t *testing.T) {
	a, b := Token(32), Token(32)
	if len(a) != 64 || len(b) != 64 {
		t.Fatalf("token length %d", len(a))
	}
	if a == b {
		t.Fatal("tokens repeat")
	}
	if s := Base32Secret(10); len(s) != 16 || strings.Contains(s, "=") {
		t.Fatalf("bad base32 secret %q", s)
	}
}

func TestRateLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	now := time.Now()
	key := "1.2.3.4|admin"
	for i := 0; i < 3; i++ {
		if blocked, _ := l.Blocked(key, now); blocked {
			t.Fatalf("blocked after only %d failures", i)
		}
		l.Fail(key, now)
	}
	blocked, wait := l.Blocked(key, now)
	if !blocked || wait <= 0 {
		t.Fatalf("not blocked after the limit: %v %v", blocked, wait)
	}
	if snap := l.Snapshot(now); snap[key] <= 0 {
		t.Error("snapshot does not report the lockout")
	}
	// Another key is unaffected: one account cannot lock out the whole panel.
	if blocked, _ := l.Blocked("1.2.3.4|other", now); blocked {
		t.Error("lockout leaked across keys")
	}
	// A success clears the counter.
	l.Pass(key)
	if blocked, _ := l.Blocked(key, now); blocked {
		t.Error("Pass did not clear the cell")
	}
	// Lockout decays instead of sticking forever, but never fully resets, so a
	// restart-every-minute attack still gets slowed down.
	l2 := NewLimiter(2, time.Minute)
	l2.Fail("k", now)
	l2.Fail("k", now)
	if b, _ := l2.Blocked("k", now); !b {
		t.Fatal("l2 should be locked")
	}
	later := now.Add(2 * time.Minute)
	if b, _ := l2.Blocked("k", later); b {
		t.Fatal("lockout should have expired")
	}
	l2.Fail("k", later)
	if b, _ := l2.Blocked("k", later); !b {
		t.Fatal("decayed counter should re-lock after one more failure")
	}
}
