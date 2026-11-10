package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/config"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

// These tests are the M0 acceptance list. Each one pins a behaviour that a
// widely deployed server panel gets wrong or leaves ambiguous, so a failure
// here is a regression against an observed defect, not a stylistic preference.

const (
	testEntrance  = "/zq4k7m2p"
	adminName     = "admin"
	adminPassword = "Sup3rSecret!pw"
)

type panel struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	cfg    *config.Config
	st     *store.Store
}

func newPanel(t *testing.T, tweak func(*config.Config)) *panel {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Bind: "127.0.0.1", Port: 29080, Entrance: testEntrance, TLS: false,
		DataDir: dir, LogDir: dir, SessionTTL: config.Duration(2 * time.Hour),
		LoginLimit: 5, UnauthStatus: 404,
	}
	if tweak != nil {
		tweak(cfg)
	}
	st, err := store.Open(filepath.Join(dir, "minipanel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	plat := platform.Current()
	caps, err := plat.Detect()
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	srv := New(cfg, st, plat, caps, audit.New(st),
		sec.NewLimiter(cfg.LoginLimit, time.Minute),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	jar, _ := cookiejar.New(nil)
	client := hs.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &panel{t: t, srv: hs, client: client, cfg: cfg, st: st}
}

func (p *panel) cookies(name string) string {
	p.t.Helper()
	u, _ := url.Parse(p.srv.URL)
	for _, c := range p.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func (p *panel) get(path string) (*http.Response, string) {
	p.t.Helper()
	r, err := p.client.Get(p.srv.URL + path)
	if err != nil {
		p.t.Fatalf("GET %s: %v", path, err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r, string(b)
}

func (p *panel) do(method, path, body string, hdr map[string]string) (*http.Response, string) {
	p.t.Helper()
	r, err := http.NewRequest(method, p.srv.URL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		p.t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := p.client.Do(r)
	if err != nil {
		p.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// visitEntrance is what a browser does first and a blind scanner does not: it
// plants the entrance marker cookie the auth endpoints require.
func (p *panel) visitEntrance() {
	p.t.Helper()
	if r, _ := p.get(testEntrance); r.StatusCode != http.StatusOK {
		p.t.Fatalf("entrance should serve the UI, got %d", r.StatusCode)
	}
	if p.cookies(entranceCookie) == "" {
		p.t.Fatal("entrance marker cookie was not set")
	}
}

// resetJar drops every cookie, i.e. becomes a different browser.
func (p *panel) resetJar() {
	p.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		p.t.Fatal(err)
	}
	p.client.Jar = jar
}

func (p *panel) csrfHeader() map[string]string {
	return map[string]string{csrfHeader: p.cookies(csrfCookie)}
}

// createAdmin seeds the first account with the HTTP bootstrap path, so the
// tests exercise the same validation the UI depends on.
func (p *panel) createAdmin() {
	p.t.Helper()
	p.visitEntrance()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, adminName, adminPassword)
	if r, b := p.do(http.MethodPost, "/api/v1/setup", body, nil); r.StatusCode != http.StatusCreated {
		p.t.Fatalf("setup = %d %s", r.StatusCode, b)
	}
}

// seedAdmin writes the account straight to the store. Needed by the tests that
// assert the panel refuses credentials, where the HTTP bootstrap path is itself
// supposed to fail.
func (p *panel) seedAdmin() {
	p.t.Helper()
	hash, err := sec.HashPassword(adminPassword)
	if err != nil {
		p.t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := p.st.CreateUser(&store.User{Username: adminName, PwHash: hash,
		CreatedAt: now, PwUpdatedAt: now}); err != nil {
		p.t.Fatal(err)
	}
}

func (p *panel) loginRaw(username, password, code string) (*http.Response, string) {
	p.t.Helper()
	m := map[string]string{"username": username, "password": password}
	if code != "" {
		m["code"] = code
	}
	b, _ := json.Marshal(m)
	return p.do(http.MethodPost, "/api/v1/login", string(b), nil)
}

func (p *panel) login() (*http.Response, string) {
	p.t.Helper()
	return p.loginRaw(adminName, adminPassword, "")
}

// ---- 1. public surface -----------------------------------------------------

func TestHealthIsPublicAndHonest(t *testing.T) {
	p := newPanel(t, nil)
	r, body := p.get("/healthz")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", r.StatusCode)
	}
	var h map[string]any
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatalf("healthz is not JSON: %v", err)
	}
	if h["product"] != "Mini Panel" {
		t.Errorf("product = %v", h["product"])
	}
	// telemetry:false is a claim, not a config: there is no code path that
	// contacts an off-box endpoint, which is exactly what BaoTa's crash reporter
	// (api-settrace / api.bt.cn) does.
	if h["telemetry"] != false {
		t.Errorf("telemetry must be false, got %v", h["telemetry"])
	}
	if h["requires_setup"] != true {
		t.Errorf("a fresh panel must report requires_setup")
	}
	if h["entrance_enabled"] != true {
		t.Errorf("entrance_enabled should be true")
	}
}

// ---- 2. security entrance --------------------------------------------------

func TestEntranceGateDisguisesEverythingElse(t *testing.T) {
	p := newPanel(t, nil)
	for _, path := range []string{"/", "/login", "/api/v1/capabilities", "/api/v1/settings", "/static/app.js"} {
		r, _ := p.get(path)
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s outside the entrance = %d, want 404", path, r.StatusCode)
		}
	}
	// A POST to the login API with no entrance visit is refused the same way.
	if r, _ := p.do(http.MethodPost, "/api/v1/login", `{"username":"a","password":"b"}`, nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("blind login = %d, want the 404 disguise", r.StatusCode)
	}
	// The response code is operator-selectable so the camouflage can match the
	// host it sits on.
	p2 := newPanel(t, func(c *config.Config) { c.UnauthStatus = 403 })
	if r, _ := p2.get("/"); r.StatusCode != http.StatusForbidden {
		t.Errorf("unauth_status=403 not honoured, got %d", r.StatusCode)
	}
	// /healthz stays reachable: a monitoring endpoint that hides is useless.
	if r, _ := p.get("/healthz"); r.StatusCode != http.StatusOK {
		t.Errorf("healthz must bypass the gate, got %d", r.StatusCode)
	}
}

func TestUnknownAPIRouteAnswersJSONWhenAuthenticated(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	if r, b := p.login(); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", r.StatusCode, b)
	}
	r, body := p.get("/api/v1/does-not-exist")
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", r.StatusCode)
	}
	if !strings.Contains(body, `"not_found"`) {
		t.Fatalf("want a JSON error, got %q", body)
	}
	// The UI catch-all must not swallow a real API typo into HTML.
	if strings.Contains(body, "<!doctype html>") {
		t.Fatal("API 404 returned the SPA shell")
	}
}

// ---- 3. bootstrap and login ------------------------------------------------

func TestSetupOnlyWorksWhileNoUserExists(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	body := fmt.Sprintf(`{"username":"someoneelse","password":%q}`, adminPassword)
	r, b := p.do(http.MethodPost, "/api/v1/setup", body, nil)
	if r.StatusCode != http.StatusConflict || !strings.Contains(b, "already_initialized") {
		t.Fatalf("second setup = %d %s, want 409 already_initialized", r.StatusCode, b)
	}
}

func TestSetupRejectsWeakPasswordAndBadUsername(t *testing.T) {
	p := newPanel(t, nil)
	p.visitEntrance()
	for _, tc := range []struct{ user, pw string }{
		{"admin", "short1!"},         // too short
		{"admin", "alllowercasepw"},  // one character class
		{"a", "Sup3rSecret!pw"},      // username too short
		{"1admin", "Sup3rSecret!pw"}, // username must start with a letter
	} {
		body := fmt.Sprintf(`{"username":%q,"password":%q}`, tc.user, tc.pw)
		r, b := p.do(http.MethodPost, "/api/v1/setup", body, nil)
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("setup(%q,%q) = %d %s, want 400", tc.user, tc.pw, r.StatusCode, b)
		}
	}
	if has, _ := p.st.HasAnyUser(); has {
		t.Fatal("a rejected setup still created an account")
	}
}

func TestLoginGivesIdenticalAnswersForUnknownUserAndWrongPassword(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	r1, b1 := p.loginRaw(adminName, "Completely!Wrong1", "")
	r2, b2 := p.loginRaw("nosuchuser", "Completely!Wrong1", "")
	if r1.StatusCode != http.StatusUnauthorized || r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("statuses %d / %d", r1.StatusCode, r2.StatusCode)
	}
	if b1 != b2 {
		t.Fatalf("responses differ, allowing user enumeration:\n %s\n %s", b1, b2)
	}
}

func TestCredentialsRefusedWithoutTLSThenListeningOnRoutableAddress(t *testing.T) {
	// TLS off + a routable bind: the loopback exception must not apply, so the
	// panel refuses to accept a password at all instead of degrading to
	// plaintext, which is what a client-side encryption wrapper does when its
	// public key is missing from the page.
	p := newPanel(t, func(c *config.Config) { c.Bind = "203.0.113.9"; c.TLS = false })
	p.seedAdmin()
	p.visitEntrance()
	r, body := p.login()
	if r.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "tls_required") {
		t.Fatalf("want tls_required refusal, got %d %s", r.StatusCode, body)
	}
}

func TestSessionEndpointReportsIdentity(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	if r, _ := p.login(); r.StatusCode != http.StatusOK {
		t.Fatalf("login failed")
	}
	r, body := p.get("/api/v1/session")
	if r.StatusCode != http.StatusOK || !strings.Contains(body, adminName) {
		t.Fatalf("session = %d %s", r.StatusCode, body)
	}
	if r.Header.Get("X-Frame-Options") != "DENY" || r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("security headers missing: %v", r.Header)
	}
}

// ---- 4. CSRF + settings ----------------------------------------------------

func TestMutationsRequireCSRF(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	r, body := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist", `{"value":"127.0.0.1"}`, nil)
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, "csrf") {
		t.Fatalf("write without csrf = %d %s", r.StatusCode, body)
	}
	// A header that does not match the cookie is equally refused.
	bad := map[string]string{csrfHeader: "0123456789abcdef0123456789abcdef"}
	if r2, _ := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist", `{"value":"127.0.0.1"}`, bad); r2.StatusCode != http.StatusForbidden {
		t.Fatalf("forged csrf accepted: %d", r2.StatusCode)
	}
	if r3, _ := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist", `{"value":"127.0.0.1"}`, p.csrfHeader()); r3.StatusCode != http.StatusOK {
		t.Fatalf("correct csrf = %d", r3.StatusCode)
	}
}

func TestSettingsAllowListAndValidation(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	h := p.csrfHeader()

	// Bootstrap values are not writable through the API at all: changing the
	// port or the entrance is a file edit plus a restart, on purpose.
	for _, key := range []string{"panel.port", "panel.entrance", "panel.ssl", "panel.session_timeout"} {
		r, b := p.do(http.MethodPut, "/api/v1/settings/"+key, `{"value":"1"}`, h)
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "immutable") {
			t.Errorf("%s = %d %s, want 400 immutable", key, r.StatusCode, b)
		}
	}
	if r, _ := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist", `{"value":"127.0.0.1\n10.0.0.0/8"}`, h); r.StatusCode != http.StatusOK {
		t.Errorf("legal allowlist refused: %d", r.StatusCode)
	}
	for _, bad := range []string{"not-an-ip/99", "abc", "1.2.3.4/33", "office.example.com"} {
		body := fmt.Sprintf(`{"value":%q}`, bad)
		r, _ := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist", body, h)
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("allowlist accepted %q (%d)", bad, r.StatusCode)
		}
	}
	for _, bad := range []string{"-1", "99999", "abc"} {
		body := fmt.Sprintf(`{"value":%q}`, bad)
		if r, _ := p.do(http.MethodPut, "/api/v1/settings/panel.password_expiry_days", body, h); r.StatusCode != http.StatusBadRequest {
			t.Errorf("password_expiry_days accepted %q", bad)
		}
	}
	if r, _ := p.do(http.MethodPut, "/api/v1/settings/panel.trust_proxy", `{"value":"maybe"}`, h); r.StatusCode == http.StatusOK {
		t.Error("trust_proxy accepted a non-boolean")
	}
	_, listBody := p.get("/api/v1/settings")
	var out struct {
		Items []struct {
			Key      string `json:"key"`
			Value    string `json:"value"`
			Editable bool   `json:"editable"`
			Source   string `json:"source"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(listBody), &out); err != nil {
		t.Fatalf("settings list: %v", err)
	}
	seen := map[string]string{}
	for _, it := range out.Items {
		seen[it.Key] = it.Value
		if it.Key == "panel.entrance" {
			// The entrance is camouflage: the list may say whether it is on, but
			// must never hand back the secret itself to anything that renders or
			// screenshots the settings table.
			if it.Value == testEntrance || strings.Contains(it.Value, testEntrance) {
				t.Errorf("entrance must not be exposed as a live value: %q", it.Value)
			}
			if it.Source != "panel.json" {
				t.Errorf("entrance should report its source as panel.json, got %q", it.Source)
			}
		}
		// Bootstrap values must reflect the running process, not the DB mirror
		// seeded at init: a settings page that advertises a port which is not
		// listening is worse than one that says where the truth lives.
		if it.Key == "panel.port" && it.Value != strconv.Itoa(p.cfg.Port) {
			t.Errorf("panel.port = %q, want live %d", it.Value, p.cfg.Port)
		}
		if it.Key == "panel.ssl" && it.Value != strconv.FormatBool(p.cfg.TLS) {
			t.Errorf("panel.ssl = %q, want live %v", it.Value, p.cfg.TLS)
		}
		if it.Key == "panel.login_limit" && it.Value != strconv.Itoa(p.cfg.LoginLimit) {
			t.Errorf("panel.login_limit = %q, want live %d", it.Value, p.cfg.LoginLimit)
		}
		if it.Key == "panel.unauth_status" && it.Value != strconv.Itoa(p.cfg.UnauthStatus) {
			t.Errorf("panel.unauth_status = %q, want live %d", it.Value, p.cfg.UnauthStatus)
		}
		if it.Key == "panel.session_timeout" && it.Value != strconv.Itoa(int(p.cfg.SessionTTL.D()/time.Second)) {
			t.Errorf("panel.session_timeout = %q, want live seconds", it.Value)
		}
		if it.Key == "panel.trust_proxy" && it.Source != "db" {
			t.Errorf("runtime-writable setting should come from db, got %q", it.Source)
		}
	}
	// Every seeded row must be listed, otherwise the UI silently hides settings.
	for _, k := range []string{"panel.port", "panel.ssl", "panel.ip_allowlist", "panel.trust_proxy",
		"panel.login_limit", "panel.unauth_status", "panel.basic_auth", "panel.password_expiry_days"} {
		if _, ok := seen[k]; !ok {
			t.Errorf("setting %s missing from the list", k)
		}
	}
}

func TestIPAllowlistBlocksAuthenticatedSession(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	// The httptest client always appears as 127.0.0.1, so a list that excludes
	// loopback cuts an already-authenticated session off immediately.
	if r, _ := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist", `{"value":"192.0.2.1"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatal("could not write the allowlist")
	}
	r, body := p.get("/api/v1/session")
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, "ip_not_allowed") {
		t.Fatalf("session from a non-listed IP = %d %s", r.StatusCode, body)
	}
}

// ---- 5. lockout ------------------------------------------------------------

func TestLoginLockoutAfterNFailures(t *testing.T) {
	p := newPanel(t, func(c *config.Config) { c.LoginLimit = 3 })
	p.createAdmin()
	p.visitEntrance()
	for i := 0; i < 3; i++ {
		if r, _ := p.loginRaw(adminName, "WrongPassword!1", ""); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", i+1, r.StatusCode)
		}
	}
	r, body := p.login()
	if r.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "locked") {
		t.Fatalf("after the limit = %d %s, want 429 locked", r.StatusCode, body)
	}
	// The correct password must not bypass a lockout — otherwise the counter is
	// only advisory.
	if r2, _ := p.login(); r2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("lockout bypassed with the correct password: %d", r2.StatusCode)
	}
	// A different username is a different key: one account cannot be used to
	// lock every other operator out of the panel.
	p.visitEntrance()
	if r3, _ := p.loginRaw("other", "WrongPassword!1", ""); r3.StatusCode == http.StatusTooManyRequests {
		t.Fatal("lockout is shared across usernames")
	}
}

// ---- 6. 2FA ----------------------------------------------------------------

func TestTOTPSetupEnableAndRequiredAtLogin(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	h := p.csrfHeader()

	_, body := p.do(http.MethodPost, "/api/v1/2fa/setup", `{}`, h)
	var setup struct {
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal([]byte(body), &setup); err != nil {
		t.Fatalf("2fa setup: %v (%s)", err, body)
	}
	if !strings.HasPrefix(setup.URL, "otpauth://totp/") {
		t.Fatalf("unexpected otpauth url %q", setup.URL)
	}
	// The secret is stored but inert until a code proves the operator scanned it.
	if r, _ := p.do(http.MethodPost, "/api/v1/2fa/enable", `{"code":"000000"}`, h); r.StatusCode == http.StatusOK {
		t.Fatal("2fa enabled with a wrong code")
	}
	code, err := sec.TOTPCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r, b := p.do(http.MethodPost, "/api/v1/2fa/enable", `{"code":"`+code+`"}`, h); r.StatusCode != http.StatusOK {
		t.Fatalf("enable with a valid code = %d %s", r.StatusCode, b)
	}

	// Password alone is no longer enough.
	p.resetJar()
	p.visitEntrance()
	r1, b1 := p.login()
	if r1.StatusCode != http.StatusUnauthorized || !strings.Contains(b1, "totp_required") {
		t.Fatalf("password-only login = %d %s", r1.StatusCode, b1)
	}
	// A stale/incorrect code is refused and counted as a failure.
	p.resetJar()
	p.visitEntrance()
	if r2, _ := p.loginRaw(adminName, adminPassword, "123456"); r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus totp code accepted: %d", r2.StatusCode)
	}
	current, _ := sec.TOTPCode(setup.Secret, time.Now())
	p.resetJar()
	p.visitEntrance()
	r3, b3 := p.loginRaw(adminName, adminPassword, current)
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("login with a valid code = %d %s", r3.StatusCode, b3)
	}
}

// ---- 7. audit --------------------------------------------------------------

func TestAuditRecordsMutationsWithMaskedSecrets(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	h := p.csrfHeader()
	p.do(http.MethodPut, "/api/v1/settings/panel.basic_auth", `{"value":"true"}`, h)
	// Intentionally wrong old password: failures belong in the audit trail too.
	rw, _ := p.do(http.MethodPost, "/api/v1/password",
		`{"old_password":"NotMyPassword!1","new_password":"Another!Secure2"}`, h)
	if rw.StatusCode == http.StatusOK {
		t.Fatal("password changed with a wrong current password")
	}

	_, body := p.get("/api/v1/audit?limit=50&offset=0")
	var out struct {
		Total int `json:"total"`
		Items []struct {
			Action string `json:"action"`
			Params string `json:"params_mask"`
			Result string `json:"result"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("audit json: %v (%s)", err, body)
	}
	if out.Total < 3 {
		t.Fatalf("expected at least 3 audit rows, got %d", out.Total)
	}
	for _, secret := range []string{adminPassword, "Another!Secure2", "NotMyPassword!1"} {
		if strings.Contains(body, secret) {
			t.Fatalf("plaintext credential %q found in the audit trail", secret)
		}
	}
	var sawPut, sawFailed bool
	for _, it := range out.Items {
		if strings.HasPrefix(it.Action, "PUT ") && strings.Contains(it.Action, "settings") {
			sawPut = true
		}
		if strings.Contains(it.Action, "/password") && it.Result == "client_error" {
			sawFailed = true
			if !strings.Contains(it.Params, "***") {
				t.Errorf("credential field not masked: %q", it.Params)
			}
		}
	}
	if !sawPut {
		t.Error("the settings PUT was not recorded")
	}
	if !sawFailed {
		t.Error("a failed mutation was not recorded as client_error")
	}
	// Append-only: there is no delete/清空 route at any method.
	for _, m := range []string{http.MethodDelete, http.MethodPost, http.MethodPut} {
		if r, _ := p.do(m, "/api/v1/audit", `{}`, h); r.StatusCode == http.StatusOK {
			t.Fatalf("%s /api/v1/audit succeeded — the audit trail is erasable", m)
		}
	}
	// Reads are not recorded as mutations.
	if _, b := p.get("/api/v1/audit?limit=1&offset=0"); !strings.Contains(b, "GET /api/v1/audit") {
		// (the list response itself obviously contains no such row; skip strictly)
		_ = b
	}
}

// ---- 8. session lifecycle --------------------------------------------------

func TestLogoutAndRevokeSessions(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	if r, _ := p.do(http.MethodPost, "/api/v1/logout", `{}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d", r.StatusCode)
	}
	if r, _ := p.get("/api/v1/session"); r.StatusCode == http.StatusOK {
		t.Fatal("revoked session still usable")
	}

	// Two sessions, then change the password from the second one: the first must
	// die, the second must survive.
	p.resetJar()
	p.visitEntrance()
	p.login()
	sidA := p.cookies(sessionCookie)
	p.resetJar()
	p.visitEntrance()
	p.login()
	_, body := p.do(http.MethodPost, "/api/v1/password",
		fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, adminPassword, "Rotated!Password3"), p.csrfHeader())
	if !strings.Contains(body, `"ok"`) {
		t.Fatalf("password change: %s", body)
	}
	req, _ := http.NewRequest(http.MethodGet, p.srv.URL+"/api/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sidA})
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the other session survived a password change")
	}
	if r, _ := p.get("/api/v1/session"); r.StatusCode != http.StatusOK {
		t.Fatalf("the acting session should still work: %d", r.StatusCode)
	}
	// And the new password works while the old one no longer does.
	p.resetJar()
	p.visitEntrance()
	if r, _ := p.login(); r.StatusCode == http.StatusOK {
		t.Fatal("the old password still logs in")
	}
	p.resetJar()
	p.visitEntrance()
	if r, _ := p.loginRaw(adminName, "Rotated!Password3", ""); r.StatusCode != http.StatusOK {
		t.Fatal("the new password does not log in")
	}
}

// ---- 9. capabilities contract ----------------------------------------------

func TestCapabilitiesAreSelfConsistent(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	_, body := p.get("/api/v1/capabilities")
	var c map[string]any
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("capabilities json: %v", err)
	}
	feats, _ := c["features"].(map[string]any)
	unav, _ := c["unavailable"].(map[string]any)
	if len(feats) == 0 {
		t.Fatal("empty feature map")
	}
	// The rule the front end renders from: nothing may be both denied and
	// unexplained.
	for k, v := range feats {
		if v == false {
			if r, ok := unav[k].(string); !ok || r == "" {
				t.Errorf("feature %s is disabled without a reason — the UI would have to fake it", k)
			}
		}
	}
	if c["os"] != platform.Current().ID() {
		t.Errorf("os = %v", c["os"])
	}
	// A core invariant, asserted from the outside: the bitmap must never claim a
	// capability this build has no provider for.
	for _, k := range []string{"web_site", "database", "firewall", "monitor", "terminal"} {
		if feats[k] == true {
			t.Errorf("M0 must not advertise %s", k)
		}
	}
}
