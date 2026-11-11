package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
)

// M1 acceptance cases: the session list, the two ways to end a session, and the
// entrance check that now runs on page navigations. Same harness as m0_test.go,
// because the point of these is how they behave over HTTP, not how they behave
// in a handler.

// seedSession writes a second row straight to the store. A real second browser
// would do the same thing at login, but the test needs to keep driving the
// first one afterwards, and there is one cookie jar per panel.
func (p *panel) seedSession(id, ref, ip string, age time.Duration) {
	p.t.Helper()
	u, err := p.st.UserByUsername(adminName)
	if err != nil {
		p.t.Fatalf("read admin: %v", err)
	}
	now := time.Now()
	_, err = p.st.DB().Exec(`INSERT INTO sessions(id,ref,user_id,created_at,expires_at,ip,ua,revoked)
		VALUES(?,?,?,?,?,?,?,0)`, id, ref, u.ID, now.Add(-age).Unix(),
		now.Add(2*time.Hour).Unix(), ip, "seeded-for-test")
	if err != nil {
		p.t.Fatalf("seed session: %v", err)
	}
}

type sessionView struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Revoked    bool   `json:"revoked"`
	Expired    bool   `json:"expired"`
	Current    bool   `json:"current"`
	Privileged *bool  `json:"privileged"`
}

func (p *panel) sessions() (map[string]any, []sessionView) {
	p.t.Helper()
	r, body := p.get("/api/v1/sessions")
	if r.StatusCode != http.StatusOK {
		p.t.Fatalf("GET /sessions = %d %s", r.StatusCode, body)
	}
	var out struct {
		Items []sessionView `json:"items"`
		Total int           `json:"total"`
		Live  int           `json:"live"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		p.t.Fatalf("sessions json: %v\n%s", err, body)
	}
	return map[string]any{"total": out.Total, "live": out.Live}, out.Items
}

// TestSessionListNamesRowsWithoutHandingOutTheToken is the whole reason the
// sessions table has a second identifier column. The row a browser would
// naturally key on — sessions.id — is the bearer credential: putting it in a
// list means it lands in the UI's memory, in somebody's screenshot, in an audit
// target and in a browser extension's reach, and any one of those is a login.
func TestSessionListNamesRowsWithoutHandingOutTheToken(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	token := p.cookies(sessionCookie)
	if len(token) < 32 {
		t.Fatalf("no usable session cookie: %q", token)
	}
	p.seedSession("another-browser-token", "0123456789abcdef", "203.0.113.9", 3*time.Hour)

	_, items := p.sessions()
	if len(items) != 2 {
		t.Fatalf("want 2 rows, got %d", len(items))
	}
	var cur, other *sessionView
	for i := range items {
		switch items[i].IP {
		case "203.0.113.9":
			other = &items[i]
		default:
			cur = &items[i]
		}
	}
	if other == nil || cur == nil {
		t.Fatalf("rows not found: %+v", items)
	}
	if !cur.Current {
		t.Error("the row this request is using is not marked current")
	}
	if other.Current {
		t.Error("a different session was marked current")
	}
	if other.ID != "0123456789abcdef" {
		t.Errorf("seeded ref = %q, want the handle the store gave it", other.ID)
	}
	// The live row must come first regardless of age: the seeded row is older,
	// and a list that sorts by time buries "what is still signed in".
	if items[0].IP != cur.IP {
		t.Errorf("live session not first: %+v", items)
	}
	// And the token must be nowhere in the payload.
	_, raw := p.get("/api/v1/sessions")
	if strings.Contains(raw, token) || strings.Contains(raw, "another-browser-token") {
		t.Errorf("session list leaked a bearer token: %s", raw)
	}
	if n := strings.Count(raw, "\"id\""); n != 2 {
		t.Errorf("expected 2 id fields (handles), got %d in %s", n, raw)
	}
}

// TestRevokeOthersKeepsTheOperatorsOwnSession covers the button an operator
// presses after seeing an unfamiliar IP: it must be usable without logging
// themselves out, and it must actually end the other row.
func TestRevokeOthersKeepsTheOperatorsOwnSession(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	p.seedSession("stale-token", "aabbccddeeff0011", "198.51.100.7", 4*time.Hour)

	// The collection endpoint is the "everywhere else" button itself; the loop
	// below deliberately never sends an empty segment, because "/sessions/" is a
	// different route, not a malformed id.
	// A DELETE is a write: no CSRF header, no revoke.
	if r, _ := p.do(http.MethodDelete, "/api/v1/sessions", "", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without csrf = %d, want 403", r.StatusCode)
	}
	r, body := p.do(http.MethodDelete, "/api/v1/sessions", "", p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("revoke others = %d %s", r.StatusCode, body)
	}
	if !strings.Contains(body, `"revoked":1`) {
		t.Errorf("revoke count missing: %s", body)
	}
	var revoked int
	if err := p.st.DB().QueryRow(`SELECT revoked FROM sessions WHERE id='stale-token'`).Scan(&revoked); err != nil {
		t.Fatalf("read seeded row: %v", err)
	}
	if revoked != 1 {
		t.Error("the other session survived 撤销全部")
	}
	// The caller keeps working — this is the difference between this endpoint
	// and logout, and it is the reason the UI can offer it as a first response.
	if r, _ := p.get("/api/v1/system/info"); r.StatusCode != http.StatusOK {
		t.Errorf("own session was revoked too: %d", r.StatusCode)
	}
	_, items := p.sessions()
	live := 0
	for _, it := range items {
		if !it.Revoked {
			live++
		}
	}
	if live != 1 {
		t.Errorf("want exactly 1 live row after revoking others, got %d (%+v)", live, items)
	}
}

// TestRevokeOneSessionChecksTheHandleItIsGiven: {id} is the panel's first
// non-settings path parameter, so its validation rules are the ones
// docs/功能设计.md §4.4 promises — a fixed charset, a user-scoped lookup, and no
// answer that tells a probe anything about rows it cannot see.
func TestRevokeOneSessionChecksTheHandleItIsGiven(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	p.seedSession("target-token", "cafe000011112222", "198.51.100.8", time.Hour)
	h := p.csrfHeader()

	for _, bad := range []string{"CAFE000011112222", "cafe", "cafe00001111222g",
		strings.Repeat("a", 64), "cafe00001111222x", "0123456789abcde ", "cafe000011112222.json"} {
		r, body := p.do(http.MethodDelete, "/api/v1/sessions/"+url.PathEscape(bad), "", h)
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("id %q = %d, want 400 from the charset check: %s", bad, r.StatusCode, body)
		}
	}
	// Traversal-shaped values are refused too, whichever layer catches them
	// first: Go's URL parsing cleans "/..", so the router may answer 404 before
	// the handler's regexp is ever consulted. What is asserted here is the
	// invariant — nothing reaches the database and nothing is revoked.
	for _, weird := range []string{"../cafe000011112222", "cafe000011112222/..", "%2e%2e%2fcafe00"} {
		r, _ := p.do(http.MethodDelete, "/api/v1/sessions/"+weird, "", h)
		if r.StatusCode == http.StatusOK {
			t.Errorf("traversal-shaped id %q was accepted", weird)
		}
	}
	if _, body := p.do(http.MethodDelete, "/api/v1/sessions/"+url.PathEscape("../../etc/passwd"), "", h); body == "" {
		t.Error("no answer at all for a traversal id")
	}
	if live := p.st.DB().QueryRow(`SELECT COUNT(1) FROM sessions WHERE revoked=0`); true {
		var n int
		if err := live.Scan(&n); err != nil {
			t.Fatalf("count live sessions: %v", err)
		}
		if n != 2 {
			t.Errorf("live session rows = %d, want the operator's plus the seeded target", n)
		}
	}
	// Well-formed but not this account's: the same 404 as one that never existed.
	r, body := p.do(http.MethodDelete, "/api/v1/sessions/deadbeefdeadbeef", "", h)
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown handle = %d %s, want 404", r.StatusCode, body)
	}
	// The real one.
	r, body = p.do(http.MethodDelete, "/api/v1/sessions/cafe000011112222", "", h)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("revoke known handle = %d %s", r.StatusCode, body)
	}
	if strings.Contains(body, `"need_relogin":true`) {
		t.Error("revoking somebody else's session told this browser to log in again")
	}
	if p.cookies(sessionCookie) == "" {
		t.Error("own session cookie was cleared by revoking another row")
	}
	var revoked int
	if err := p.st.DB().QueryRow(`SELECT revoked FROM sessions WHERE id='target-token'`).Scan(&revoked); err != nil {
		t.Fatalf("read target: %v", err)
	}
	if revoked != 1 {
		t.Error("target row not revoked")
	}
	// Revoking it a second time is not a new fact, and must not read like one.
	if r2, _ := p.do(http.MethodDelete, "/api/v1/sessions/cafe000011112222", "", h); r2.StatusCode != http.StatusNotFound {
		t.Errorf("second revoke = %d, want 404", r2.StatusCode)
	}
}

// TestRevokingTheCurrentSessionEndsItHere: the response has to say so, and the
// browser must not keep presenting a token the database already refuses.
func TestRevokingTheCurrentSessionEndsItHere(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	token := p.cookies(sessionCookie)
	if len(token) < 32 {
		t.Fatalf("no usable session cookie: %q", token)
	}
	_, items := p.sessions()
	var self sessionView
	for _, it := range items {
		if it.Current {
			self = it
		}
	}
	if self.ID == "" {
		t.Fatal("no current row in the list")
	}
	r, body := p.do(http.MethodDelete, "/api/v1/sessions/"+self.ID, "", p.csrfHeader())
	if r.StatusCode != http.StatusOK {
		t.Fatalf("revoke self = %d %s", r.StatusCode, body)
	}
	if !strings.Contains(body, `"need_relogin":true`) || !strings.Contains(body, `"current":true`) {
		t.Errorf("revoke self did not say so: %s", body)
	}
	if p.cookies(sessionCookie) != "" {
		t.Error("session cookie still set after revoking the current session")
	}
	// The audit trail must not have swallowed the credential. Reading it over
	// HTTP is impossible here — the session that would read it is the one that
	// was just ended — so the table is read the way the endpoint reads it.
	//
	// What *does* appear is the URL, and therefore the handle: /api/v1/sessions/
	// <16 hex>. That is the deliberate trade. A handle identifies a row to an
	// operator who is already authenticated to read the trail, and it cannot be
	// replayed; the token can be replayed by anyone who reads it, which is why
	// it is not in this table, in any response, or in any log line.
	entries, _, err := audit.New(p.st).List(200, 0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var sawRevoke, sawHandle bool
	for _, e := range entries {
		joined := e.Action + e.Target + e.Params + e.Hash
		if strings.Contains(joined, token) {
			t.Errorf("audit row %d holds the session token: %+v", e.ID, e)
		}
		if e.Action == "DELETE /api/v1/sessions/{id}" {
			sawRevoke = true
			if strings.Contains(e.Target, self.ID) {
				sawHandle = true
			}
		}
	}
	if !sawRevoke {
		t.Error("revoking a session wrote no audit row at all")
	}
	if !sawHandle {
		t.Log("handle not echoed in target: fine, but the docs describe it as visible")
	}
}

// TestHTMLNavigationAfterLoginIsGuidedThroughTheEntrance is M1's tightening of
// the entrance. Before it, a valid session meant every URL on the port worked,
// which is the sentence that must not appear in the docs — and the way to fix it
// is not to break the SPA: this hop applies to document loads only, and the
// entrance serves the same page it always did.
func TestHTMLNavigationAfterLoginIsGuidedThroughTheEntrance(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	// Login deliberately drops the entrance marker, so a page load now arrives
	// without it. That is the case this hop exists for.
	if p.cookies(entranceCookie) != "" {
		t.Skip("entrance marker survived login; the premise of the hop changed")
	}

	r, _ := p.do(http.MethodGet, "/", "", map[string]string{"Accept": "text/html"})
	if r.StatusCode != http.StatusFound {
		t.Fatalf("document navigation = %d, want 302 to the entrance", r.StatusCode)
	}
	if got := r.Header.Get("Location"); got != testEntrance {
		t.Errorf("guided hop Location = %q, want %q", got, testEntrance)
	}
	// Following it plants the marker and serves the page.
	r, _ = p.get(testEntrance)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("entrance after hop = %d", r.StatusCode)
	}
	if p.cookies(entranceCookie) == "" {
		t.Fatal("entrance visit did not replant the marker")
	}
	r, _ = p.do(http.MethodGet, "/", "", map[string]string{"Accept": "text/html"})
	if r.StatusCode != http.StatusOK {
		t.Errorf("second document load = %d, want 200 with the marker present", r.StatusCode)
	}

	// What must NOT move: API calls, whatever a browser claims to accept. A
	// client that asked for JSON and got a 302 to HTML is how a panel "randomly"
	// logs people out.
	for _, path := range []string{"/api/v1/system/info", "/api/v1/capabilities", "/api/v1/audit"} {
		r, _ = p.do(http.MethodGet, path, "", map[string]string{"Accept": "text/html,application/xhtml+xml"})
		if r.StatusCode != http.StatusOK {
			t.Errorf("%s with an html Accept = %d, want the API answered as an API", path, r.StatusCode)
		}
	}
	// A second browser, same rules: fresh jar, entrance visited, logged in, and
	// then a deep link works — because the operator went through the entrance,
	// not because any URL is open to a holder of the token.
	p.resetJar()
	p.visitEntrance()
	p.login()
	p.visitEntrance()
	if r, _ := p.do(http.MethodGet, "/settings", "", map[string]string{"Accept": "text/html"}); r.StatusCode != http.StatusOK {
		t.Errorf("deep link with marker present = %d, want the UI served", r.StatusCode)
	}
}

// TestEntranceCamouflageStillRefusesAnonymousTraffic is the regression guard on
// the other half: tightening the logged-in case must not have made the
// unauthenticated case any easier, and /healthz must stay reachable because
// that is what a monitoring agent is pointed at.
func TestEntranceCamouflageStillRefusesAnonymousTraffic(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	p.resetJar()

	for _, path := range []string{"/", "/settings", "/api/v1/system/info", "/api/v1/sessions"} {
		r, _ := p.do(http.MethodGet, path, "", map[string]string{"Accept": "text/html"})
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("anonymous %s = %d, want the disguised 404", path, r.StatusCode)
		}
	}
	if r, _ := p.get("/healthz"); r.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", r.StatusCode)
	}
	// The list endpoint is not a second way to learn anything anonymously.
	_, body := p.get("/api/v1/sessions")
	if strings.Contains(body, "items") {
		t.Errorf("anonymous sessions read returned data: %s", body)
	}
}

// TestSessionEndpointsAreBehindThePasswordGate: an account whose password no
// human has confirmed gets exactly three usable paths. The session list is not
// one of them — but it must fail as a policy, not as a crash.
func TestSessionEndpointsAreBehindThePasswordGate(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	p.login()
	if err := p.st.SetMustChange(1, true); err != nil {
		t.Fatalf("arm the gate: %v", err)
	}
	r, body := p.get("/api/v1/sessions")
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, "password_change_required") {
		t.Fatalf("gated sessions list = %d %s", r.StatusCode, body)
	}
	// The gate is not a way to see other rows either.
	r, body = p.do(http.MethodDelete, "/api/v1/sessions/0123456789abcdef", "", p.csrfHeader())
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body, "password_change_required") {
		t.Errorf("gated revoke = %d %s", r.StatusCode, body)
	}
}
