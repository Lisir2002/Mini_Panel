package api

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The session list is M1's "who is logged in as me, and from where" page, and
// the only place the panel names one of its own live credentials to a browser.
//
// Two rules follow from what a row actually is:
//
//   - sessions.id is the bearer token. It is never serialised, never logged and
//     never appears in an audit target. The response carries sessions.ref
//     instead, a random handle with no authority of its own (store migration v3).
//   - Every query filters by user_id as well, so a guessed ref belonging to
//     another account answers "no such session" rather than touching anything.

// sessionRefPattern is exactly what migration v3 stores: 8 random bytes as hex.
// Anything else is a typo or a probe, and it is refused before it reaches SQL.
var sessionRefPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// currentRef resolves the token this request arrived with to its public handle,
// so the list can mark the row the operator is actually standing on.
func (s *Server) currentRef(r *http.Request) (string, bool) {
	u := CurrentUser(r)
	if u == nil || u.SID == "" {
		return "", false
	}
	ref, found, err := s.Store.RefByID(u.SID)
	if err != nil || ref == "" {
		return "", false
	}
	return ref, found
}

// handleSessionsList: GET /api/v1/sessions
func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	rows, err := s.Store.ListSessions(u.ID, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取会话失败")
		return
	}
	self, _ := s.currentRef(r)
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(rows))
	live := 0
	for _, row := range rows {
		expired := row.ExpiresAt <= now
		if !row.Revoked && !expired {
			live++
		}
		out = append(out, map[string]any{
			"id":         row.Ref, // the public handle, never the token
			"ip":         row.IP,
			"user_agent": row.UserAgent,
			"created_at": row.CreatedAt,
			"expires_at": row.ExpiresAt,
			"revoked":    row.Revoked,
			"expired":    expired,
			"current":    row.Ref != "" && row.Ref == self,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": out,
		"total": len(out),
		"live":  live,
	})
}

// handleSessionRevoke: DELETE /api/v1/sessions/{id}
//
// {id} is a session ref, and the panel's first path parameter that is not a
// settings key. It is validated against a fixed charset above and reaches the
// database only as a bound parameter in a user-scoped statement — the two
// conditions docs/功能设计.md §4.4 requires before contract_test.go may widen
// its path-parameter whitelist.
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	ref := strings.TrimSpace(chiParam(r, "id"))
	if !sessionRefPattern.MatchString(ref) {
		writeErr(w, http.StatusBadRequest, "bad_request", "会话 ID 格式不正确（应为 16 位十六进制）")
		return
	}
	self, _ := s.currentRef(r)
	ok, err := s.Store.RevokeByRef(u.ID, ref)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "撤销会话失败")
		return
	}
	if !ok {
		// Unknown, already revoked, or not this account's. Identical answers on
		// purpose: a list endpoint must not become a way to learn which sessions
		// existed a moment ago.
		writeErr(w, http.StatusNotFound, "not_found", "没有可撤销的会话（不存在、已撤销，或不属于当前账号）")
		return
	}
	current := ref == self && self != ""
	if current {
		// Revoking the session you are using ends it here, not on the next
		// request: the cookie is cleared so the browser stops presenting a token
		// the database already refuses.
		s.clearSessionCookies(w, r)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "revoked": 1, "current": current, "need_relogin": current,
	})
}

// handleSessionsRevokeOthers: DELETE /api/v1/sessions
//
// "Log out everywhere except here." The caller's own session survives on
// purpose: the operation an operator wants to be able to perform — dropping
// other browsers after seeing an unfamiliar IP — must not require logging
// themselves out and starting again, and the one place a session should end is
// logout.
func (s *Server) handleSessionsRevokeOthers(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	self, _ := s.currentRef(r)
	n, err := s.Store.RevokeOthers(u.ID, self)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "撤销会话失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n, "kept_current": self != ""})
}
