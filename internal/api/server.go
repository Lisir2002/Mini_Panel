// Package api is the panel's HTTP surface: one REST API described by
// internal/api/openapi/panel.yaml, plus the single WebSocket channel that will
// carry the terminal and task streams from M4 onwards.
//
// Two rules, both learned by auditing a widely deployed server panel:
//  1. No reflection. Every route maps to one handler. Nothing resolves an
//     arbitrary request parameter onto an arbitrary class or method — the
//     pattern where one query parameter picks both the module and the method
//     reachable from the public network.
//  2. The "disguise" response is camouflage, never access control. Access
//     control is bind address + authentication + optional IP allowlist.
package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/config"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
	"github.com/Lisir2002/Mini_Panel/webui"
)

const (
	sessionCookie  = "mp_session"
	csrfCookie     = "mp_csrf"
	csrfHeader     = "X-Mini-CSRF"
	entranceCookie = "mp_entrance"
)

type ctxKey string

const ctxUserKey ctxKey = "user"

// trustProxy enables X-Forwarded-For parsing. Off by default: with it on, a
// scanner could spoof the source address and walk past the per-IP lockout.
var trustProxy atomic.Bool

// SetTrustProxy is called once at startup from the settings table.
func SetTrustProxy(on bool) { trustProxy.Store(on) }

// Server holds every dependency a handler needs. Handlers stay thin: validate,
// call into internal/core, write.
type Server struct {
	Cfg     *config.Config
	Store   *store.Store
	Plat    platform.Platform
	Caps    *platform.Capabilities
	Audit   *audit.Logger
	Limiter *sec.Limiter
	Log     *slog.Logger

	router chi.Router
}

func New(cfg *config.Config, st *store.Store, plat platform.Platform, caps *platform.Capabilities,
	al *audit.Logger, lim *sec.Limiter, logger *slog.Logger) *Server {
	s := &Server{Cfg: cfg, Store: st, Plat: plat, Caps: caps, Audit: al, Limiter: lim, Log: logger}
	s.router = s.routes()
	return s
}

// siteRoot is empty when the server was built without a platform (tests).
func (s *Server) siteRoot() string {
	if s.Plat == nil {
		return ""
	}
	return s.Plat.SiteRoot()
}

func (s *Server) Handler() http.Handler { return s.router }

// routes is the whole table. An endpoint added here without a matching entry in
// openapi/panel.yaml fails `make check-contract`.
func (s *Server) routes() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(s.securityHeaders)
	r.Use(s.entranceGate)

	r.Get("/healthz", s.handleHealth)

	// The entrance is the only unauthenticated page: a random path segment in
	// front of the login form, the same role a hidden admin path plays elsewhere.
	if s.Cfg.Entrance != "" {
		r.Get(s.Cfg.Entrance, s.handleEntrance)
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/login", s.handleLogin)
		// Bootstrap only: handleSetup refuses once any user exists, so this is not
		// a permanent unauthenticated account-creation endpoint.
		r.Post("/setup", s.handleSetup)

		r.Group(func(r chi.Router) {
			r.Use(s.requireSession)
			r.Use(s.csrf)
			r.Use(s.auditWrites)

			r.Post("/logout", s.handleLogout)
			r.Get("/session", s.handleSession)

			r.Get("/capabilities", s.handleCapabilities)
			r.Get("/system/info", s.handleSystemInfo)

			// M2 third slice: static sites. GET lists only panel-owned configs;
			// POST and DELETE go through csrf() and auditWrites() like every other
			// write, and the provider runs `nginx -t` before it reloads.
			// M2 sixth slice adds PUT .../php: binding a site to one detected fpm
			// version, with the same test-before-reload and audit rules.
			r.Get("/sites", s.handleSitesList)
			r.Post("/sites", s.handleSiteCreate)
			r.Put("/sites/{name}", s.handleSiteUpdate)
			r.Delete("/sites/{name}", s.handleSiteDelete)
			r.Put("/sites/{name}/php", s.handleSitePHP)
			r.Post("/sites/{name}/tls", s.handleSiteTLSSet)
			r.Delete("/sites/{name}/tls", s.handleSiteTLSClear)
			r.Post("/sites/{name}/acme", s.handleSiteACME)

			// M1: the last page of the milestone. Read-only by construction — the
			// remedies it lists are commands, and this panel has no endpoint that
			// runs a command.
			r.Get("/lockout-risks", s.handleLockoutRisks)

			r.Get("/settings", s.handleSettingsList)
			r.Put("/settings/{key}", s.handleSettingsPut)

			r.Get("/audit", s.handleAudit)

			// M1: the session list becomes a page instead of a table nobody reads.
			// Reading it is a GET; both ways of ending a session are DELETEs, so
			// they pass through csrf() and auditWrites() like every other write.
			r.Get("/sessions", s.handleSessionsList)
			r.Delete("/sessions", s.handleSessionsRevokeOthers)
			r.Delete("/sessions/{id}", s.handleSessionRevoke)

			r.Post("/2fa/setup", s.handleTOTPSetup)
			r.Post("/2fa/enable", s.handleTOTPEnable)
			r.Post("/password", s.handlePasswordChange)
		})
	})

	r.Handle("/*", s.serveUI())
	// Anything that reaches here is an unmatched method/path pair: /api/* only,
	// because "/*" above already absorbs every UI path. Answering these as JSON
	// keeps API clients from having to parse HTML to discover a typo.
	r.NotFound(s.handleNotFound)
	r.MethodNotAllowed(s.handleMethodNotAllowed)
	return r
}

// ---- middleware -----------------------------------------------------------

// securityHeaders is the HTTP-level baseline. BaoTa additionally pins
// `<meta name=referer content=no-referrer>` and suppresses history
// back-navigation; these headers express the same intent where it belongs.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// entranceGate enforces the security entrance. With an entrance configured, an
// unauthenticated request for any other path is answered exactly like a
// non-existent resource, and the login API refuses requests that were not
// preceded by a visit to the entrance. BaoTa rejects a direct POST to its login
// endpoint for the same reason; this is a usability-preserving copy of that idea
// with no code borrowed.
//
// What this is and is not, stated plainly because it is easy to misread:
//
//   - It is camouflage for unauthenticated probing. A scanner walking the common
//     paths sees 404s everywhere and cannot tell that a panel is behind port
//     29080, which is the entire value.
//   - It is NOT an authorisation layer. Authentication is the session token, its
//     expiry, the IP allowlist, CSRF and the lockout; the entrance only decides
//     whether an anonymous visitor can find the login form, and M1's addition —
//     the guided hop below for page navigations — only decides which URL a
//     session can be *pointed at* without having visited the entrance in the
//     last hour. It does not mitigate XSS or a leaked cookie: an attacker
//     holding a session that bounces still ends up served by the entrance.
func (s *Server) entranceGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ent := s.Cfg.Entrance
		if ent == "" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == ent || strings.HasPrefix(r.URL.Path, ent+"/") {
			next.ServeHTTP(w, r)
			return
		}
		if hasSession(r) {
			// M1 tightening. Login deliberately drops the entrance marker — it is
			// single-use, and keeping it would mean an attacker who steals the
			// marker but not the session can POST credentials from anywhere — so
			// every honest page load after a login arrives without it. Send those
			// requests through the entrance once, which replants the marker and
			// serves the same page.
			//
			// Only page navigations take the hop. API calls and static assets are
			// answered exactly as before, because a fetch that silently returns a
			// 302-to-HTML is how a SPA ends up "randomly" logging people out, and
			// this check is camouflage maintenance, not a session control.
			if isPageNavigation(r) && !s.entranceMarked(r) {
				s.log().Info("entrance: guided hop", "path", r.URL.Path, "ip", clientIP(r))
				http.Redirect(w, r, ent, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/v1/login" || r.URL.Path == "/api/v1/setup" {
			if !s.entranceMarked(r) {
				s.disguise(w, r, "auth endpoint used without entrance visit")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		s.disguise(w, r, "path outside entrance")
	})
}

// isPageNavigation is a browser asking for a document, and nothing else: a
// fetch sends */* or a type, a <script src> sends its own accept list, curl
// defaults to */*. Deliberately narrow — treating anything non-JSON as a
// navigation would bounce half the panel's own UI.
func isPageNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func hasSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && len(c.Value) >= 16
}

func (s *Server) entranceMarked(r *http.Request) bool {
	c, err := r.Cookie(entranceCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.Cfg.Entrance)) == 1
}

// disguise answers "nothing here" with the configured status code.
//
// The body is a neutral HTML error page rather than Go's default
// `http.Error` text/plain, because "404 Not Found" in 10 bytes of plain text is
// itself a fingerprint of the run-time, and the whole point of this response is
// that a probe learns nothing. It is not a fake nginx page either: this process
// *is* the web server here, so serving an ordinary 404 is the truth, while
// copying BaoTa's trick of dressing an unauthenticated answer up as somebody
// else's error page misleads the operator during incident response just as much
// as it misleads the scanner. Nothing in the body names the product or version.
func (s *Server) disguise(w http.ResponseWriter, r *http.Request, reason string) {
	code := s.Cfg.UnauthStatus
	if code == 444 {
		s.log().Info("disguise: hang up", "reason", reason, "path", r.URL.Path)
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	s.log().Info("disguise", "reason", reason, "path", r.URL.Path, "ip", clientIP(r))
	text := http.StatusText(code)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	// The inline icon is not decoration: without a <link rel=icon> the browser
	// fires a second request for /favicon.ico, which turns one probe into two
	// log lines and two disguised answers.
	fmt.Fprintf(w, "<!doctype html><html><head><meta charset=utf-8><title>%[1]s</title>"+
		`<link rel="icon" href="data:,">`+
		"<style>body{font:14px/1.6 system-ui,sans-serif;color:#333;margin:3rem auto;max-width:40rem}</style>"+
		"</head><body><h1>%[1]s</h1><p>%[2]s</p></body></html>\n", text, text)
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.disguise(w, r, "no session cookie")
			return
		}
		uid, uname, expires, ok := s.lookupSession(c.Value)
		if !ok {
			s.disguise(w, r, "unknown or revoked session")
			return
		}
		if time.Now().After(expires) {
			_, _ = s.Store.DB().Exec(`UPDATE sessions SET revoked=1 WHERE id=?`, c.Value)
			s.disguise(w, r, "expired session")
			return
		}
		if !s.ipAllowed(clientIP(r)) {
			writeErr(w, http.StatusForbidden, "ip_not_allowed", "当前 IP 不在面板授权列表中")
			return
		}
		// A password that a human never chose — set by the CLI, or older than the
		// expiry policy — is not usable until it is replaced. Three paths stay
		// open so there is a way to replace it: who am I, change it, leave.
		// Exact paths only; a prefix would be a second, larger attack surface.
		if err := s.passwordGate(uid, r); err != "" {
			writeErr(w, http.StatusForbidden, "password_change_required", err)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey,
			&SessionUser{ID: uid, Username: uname, SID: c.Value})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// passwordGate returns a non-empty message when the account must change its
// password and this request is not one of the three that can do it.
func (s *Server) passwordGate(uid int64, r *http.Request) string {
	switch r.URL.Path {
	case "/api/v1/session", "/api/v1/password", "/api/v1/logout":
		return ""
	}
	u, err := s.Store.UserByID(uid)
	if err != nil || u == nil || !u.MustChangePW {
		return ""
	}
	if s.passwordExpired(u) {
		return "口令已过期，请先在“账号安全”中修改口令后再使用面板"
	}
	return "该账号的口令由 CLI 设置，尚未由本人确认；请先修改口令"
}

func (s *Server) ipAllowed(ip string) bool {
	raw, _ := s.Store.GetSetting("panel.ip_allowlist")
	if strings.TrimSpace(raw) == "" {
		return true
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == ip {
			return true
		}
		if _, block, err := net.ParseCIDR(line); err == nil {
			if pip := net.ParseIP(ip); pip != nil && block.Contains(pip) {
				return true
			}
		}
	}
	return false
}

// csrf is double-submit: a random token in a JS-readable cookie must be echoed
// in a header on every state-changing request. The session cookie is already
// SameSite=Strict, so this is defence in depth, not the primary control.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		ck, err := r.Cookie(csrfCookie)
		hv := r.Header.Get(csrfHeader)
		if err != nil || hv == "" || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(hv)) != 1 {
			writeErr(w, http.StatusForbidden, "csrf", "CSRF token 缺失或不匹配")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auditWrites records every mutation, successful or not. Reads are not recorded
// here; they belong in the access log.
func (s *Server) auditWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()

		var reqBody []byte
		if r.Body != nil {
			// Bound the buffered copy: the audit trail must never become a way to
			// exhaust panel memory with a large request body. The handler still
			// receives the whole body: replaying only the captured prefix would
			// silently truncate certificate uploads at the audit boundary.
			reqBody, _ = io.ReadAll(io.LimitReader(r.Body, 64<<10))
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBody), r.Body))
		}

		rw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(rw, r)

		u := CurrentUser(r)
		name := "anonymous"
		if u != nil {
			name = u.Username
		}
		s.Audit.Write(audit.Entry{
			User:    name,
			IP:      clientIP(r),
			Action:  r.Method + " " + routePattern(r),
			Target:  r.URL.Path,
			Params:  audit.Map(reqBody),
			Result:  resultOf(rw.Status()),
			Elapsed: time.Since(start),
		})
	})
}

func resultOf(status int) string {
	switch {
	case status >= 500:
		return "server_error"
	case status >= 400:
		return "client_error"
	case status == 0:
		return "ok"
	default:
		return "ok"
	}
}

func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return r.URL.Path
}

// ---- shared helpers -------------------------------------------------------

// SessionUser is the authenticated principal attached to the request context.
// It is a single struct today; M6 (sub-accounts) turns the concrete username
// into one field of a richer principal without touching the handlers.
type SessionUser struct {
	ID       int64
	Username string
	SID      string
}

// CurrentUser returns the authenticated principal, or nil.
func CurrentUser(r *http.Request) *SessionUser {
	if v, ok := r.Context().Value(ctxUserKey).(*SessionUser); ok {
		return v
	}
	return nil
}

func clientIP(r *http.Request) string {
	if trustProxy.Load() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, map[string]any{
		"error": map[string]string{"kind": kind, "message": msg},
	})
}

// decodeBody reads a bounded JSON body into v.
func decodeBody(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) lookupSession(id string) (int64, string, time.Time, bool) {
	var (
		uid     int64
		name    string
		exp     int64
		revoked int
	)
	err := s.Store.DB().QueryRow(`SELECT s.user_id, u.username, s.expires_at, s.revoked
		FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?`, id).
		Scan(&uid, &name, &exp, &revoked)
	if err != nil {
		return 0, "", time.Time{}, false
	}
	if revoked != 0 {
		return 0, "", time.Time{}, false
	}
	return uid, name, time.Unix(exp, 0), true
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// embeddedUI returns the compiled front end, or nil when the binary was built
// without web/dist (development builds of the API only).
func embeddedUI() fs.FS {
	sub, err := fs.Sub(webui.Assets, "dist")
	if err != nil {
		return nil
	}
	return sub
}
