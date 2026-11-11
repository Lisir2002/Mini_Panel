package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

// handleEntrance is the single unauthenticated page. Visiting it plants the
// entrance marker cookie that /api/v1/login then requires, which is what makes a
// blind POST to the login endpoint fail — the same shape as BaoTa's
// admin_auth/session check, without depending on a referer header or a User-Agent
// heuristic.
func (s *Server) handleEntrance(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     entranceCookie,
		Value:    s.Cfg.Entrance,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
	s.serveUI().ServeHTTP(w, r)
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

// credentialsAllowed is the transport rule for anything that carries a secret.
//
// It fails closed: no TLS, no credentials. The single exception is a panel bound
// to a loopback address being reached from a loopback client, which is how the
// dev server and the Playwright harness run without a certificate; a panel
// listening on a routable interface can never take that shortcut, so an
// accidental `tls: false` in production cannot turn into plaintext passwords.
//
// There is no client-side encryption wrapper here. The usual one — encrypt the
// password with a public key baked into the page — silently sends it in the
// clear whenever that key is missing from the response, which is a fallback
// path an attacker can force.
func (s *Server) credentialsAllowed(r *http.Request) bool {
	if s.Cfg.TLS && r.TLS != nil {
		return true
	}
	return isLoopback(s.Cfg.Bind) && isLoopback(clientIP(r))
}

// handleLogin authenticates and mints a session.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Fail closed rather than degrade: client-side "crypto" that falls back to
	// plaintext when its key is absent is worse than no crypto, because the
	// operator believes the password is protected. TLS or nothing.
	if !s.credentialsAllowed(r) {
		writeErr(w, http.StatusServiceUnavailable, "tls_required",
			"面板未启用 TLS，拒绝接收凭据。请启用 panel.tls 后重试。")
		return
	}
	var c credentials
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	c.Username = strings.TrimSpace(c.Username)
	ip := clientIP(r)

	if has, err := s.Store.HasAnyUser(); err != nil || !has {
		writeErr(w, http.StatusPreconditionFailed, "setup_required",
			"尚未创建面板管理员账号，请先调用 POST /api/v1/setup")
		return
	}

	key := ip + "|" + c.Username
	if blocked, wait := s.Limiter.Blocked(key, time.Now()); blocked {
		s.recordLogin(ip, c.Username, false, "locked", r)
		writeErr(w, http.StatusTooManyRequests, "locked",
			"登录失败次数过多，请在 "+durationHuman(wait)+" 后重试")
		return
	}

	u, err := s.Store.UserByUsername(c.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusInternalServerError, "store", "读取账号失败")
		return
	}
	if u == nil || !sec.VerifyPassword(u.PwHash, c.Password) {
		s.Limiter.Fail(key, time.Now())
		s.recordLogin(ip, c.Username, false, "bad_credentials", r)
		// Identical response for unknown user and wrong password, on purpose.
		writeErr(w, http.StatusUnauthorized, "bad_credentials", "用户名或密码错误")
		return
	}
	if u.TOTPEnabled {
		if strings.TrimSpace(c.Code) == "" {
			writeErr(w, http.StatusUnauthorized, "totp_required", "请输入动态口令")
			return
		}
		if !sec.VerifyTOTP(u.TOTPSecret, c.Code, time.Now()) {
			s.Limiter.Fail(key, time.Now())
			s.recordLogin(ip, c.Username, false, "bad_totp", r)
			writeErr(w, http.StatusUnauthorized, "bad_totp", "动态口令不正确")
			return
		}
	}
	s.Limiter.Pass(key)
	s.recordLogin(ip, c.Username, true, "", r)
	_ = s.Store.TouchLogin(u.ID, ip)
	s.pruneSessions()

	// Expiry is judged here, once, at the moment a credential is proven — not
	// silently in the middle of a working session, which would cut an operator
	// off mid-task. The flag is persisted so the CLI and doctor see the same
	// state the gate enforces, and the session is still minted: the only way to
	// clear it is POST /password, which needs a session to carry CSRF.
	expired := s.passwordExpired(u)
	if expired && !u.MustChangePW {
		_ = s.Store.SetMustChange(u.ID, true)
		u.MustChangePW = true
	}

	sid := sec.Token(32)
	if err := s.newSession(sid, u.ID, ip, r.UserAgent()); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "创建会话失败")
		return
	}
	csrf := sec.Token(16)
	s.setSessionCookies(w, r, sid, csrf)

	s.Audit.Write(auditEntry(r, u.Username, "POST /api/v1/login", "/api/v1/login", nil, "ok"))
	writeJSON(w, http.StatusOK, map[string]any{
		"username":         u.Username,
		"csrf":             csrf,
		"totp_enabled":     u.TOTPEnabled,
		"must_change_pw":   u.MustChangePW,
		"password_expired": expired,
		"password_changed": u.PwUpdatedAt,
		"expires_at":       time.Now().Add(s.Cfg.SessionTTL.D()).Unix(),
	})
}

// passwordExpired reports whether panel.password_expiry_days has passed since
// the current password was set. 0 or an unparsable value means "no expiry", and
// a password that has no recorded change time (a database written before this
// policy existed) is never treated as expired — guessing a date would lock
// people out for a policy nobody configured.
func (s *Server) passwordExpired(u *store.User) bool {
	raw, err := s.Store.GetSetting("panel.password_expiry_days")
	if err != nil {
		return false
	}
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days <= 0 || u.PwUpdatedAt <= 0 {
		return false
	}
	return time.Now().After(time.Unix(u.PwUpdatedAt, 0).Add(time.Duration(days) * 24 * time.Hour))
}

// handleSetup creates the first administrator. It is reachable only while the
// users table is empty, which is also what makes a re-run a no-op instead of an
// account takeover primitive.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.credentialsAllowed(r) {
		writeErr(w, http.StatusServiceUnavailable, "tls_required", "面板未启用 TLS，拒绝接收凭据")
		return
	}
	if has, _ := s.Store.HasAnyUser(); has {
		writeErr(w, http.StatusConflict, "already_initialized", "管理员账号已存在")
		return
	}
	var c credentials
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	c.Username = strings.TrimSpace(c.Username)
	if err := sec.ValidateUsername(c.Username); err != nil {
		writeErr(w, http.StatusBadRequest, "username", err.Error())
		return
	}
	if err := sec.ValidatePassword(c.Password); err != nil {
		writeErr(w, http.StatusBadRequest, "password", err.Error())
		return
	}
	hash, err := sec.HashPassword(c.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "kdf", "口令哈希失败")
		return
	}
	now := time.Now()
	u := &store.User{Username: c.Username, PwHash: hash, CreatedAt: now.Unix(),
		PwUpdatedAt: now.Unix(), MustChangePW: false}
	if err := s.Store.CreateUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "创建账号失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"username": u.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if u := CurrentUser(r); u != nil {
		_, _ = s.Store.DB().Exec(`UPDATE sessions SET revoked=1 WHERE id=?`, u.SID)
	}
	s.clearSessionCookies(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	// Read from the row, not from the token: the CLI can set or clear this flag
	// while a session is alive, and a page that reloaded has to know which of
	// the two states it is in before it starts issuing calls that would 403.
	db, err := s.Store.UserByID(u.ID)
	mustChange := err == nil && db != nil && db.MustChangePW
	expired := err == nil && db != nil && s.passwordExpired(db)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":         u.Username,
		"csrf":             csrfFromRequest(r),
		"platform":         s.Caps.OS,
		"must_change_pw":   mustChange,
		"password_expired": expired,
	})
}

func csrfFromRequest(r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil {
		return c.Value
	}
	return ""
}

// ---- session plumbing -----------------------------------------------------

// newSession stores a minted token plus its public handle (sessions.ref, added
// by migration v3). The handle exists so the session list can name a row to the
// browser without ever showing the token that row is keyed by; it is not a
// second credential — every query that takes it is also scoped by user_id.
func (s *Server) newSession(id string, userID int64, ip, ua string) error {
	now := time.Now()
	_, err := s.Store.DB().Exec(`INSERT INTO sessions(id,ref,user_id,created_at,expires_at,ip,ua,revoked)
		VALUES(?,?,?,?,?,?,?,0)`, id, sec.Token(8), userID, now.Unix(),
		now.Add(s.Cfg.SessionTTL.D()).Unix(), ip, ua)
	return err
}

func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, sid, csrf string) {
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sid, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.Cfg.SessionTTL.D().Seconds())})
	// Deliberately readable by JS: this is the double-submit token.
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/",
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.Cfg.SessionTTL.D().Seconds())})
	// The entrance marker is single-use; drop it once authenticated.
	http.SetCookie(w, &http.Cookie{Name: entranceCookie, Value: "", Path: "/", MaxAge: -1})
}

func (s *Server) clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil
	for _, n := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode})
	}
}

func (s *Server) recordLogin(ip, username string, ok bool, reason string, r *http.Request) {
	if username == "" {
		username = "<empty>"
	}
	if len(username) > 64 {
		username = username[:64]
	}
	_, _ = s.Store.DB().Exec(`INSERT INTO login_events(at,ip,username,ok,reason,ua) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), ip, username, b2i(ok), reason, truncate(r.UserAgent(), 200))
}

func (s *Server) pruneSessions() {
	_, _ = s.Store.DB().Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Add(-24*time.Hour).Unix())
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func durationHuman(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strings.TrimSuffix(d.Truncate(time.Second).String(), "0s")
	case d < time.Hour:
		return strings.TrimSuffix(d.Truncate(time.Minute).String(), "0s")
	default:
		return strings.TrimSuffix(d.Truncate(time.Minute).String(), "0s")
	}
}
