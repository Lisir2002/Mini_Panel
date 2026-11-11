// Package store keeps all persistent state in one SQLite file.
//
// Deliberate departure from BaoTa: state is never expressed as "does data/x.pl
// exist". On that panel `data/bind.pl` is a one-byte empty file that reads as
// "account bound" while the UI says the opposite. Every flag here is an explicit
// row with a typed value, created by a versioned migration.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// schemaVersion is the shape this binary expects. Migrations only ever move
// forward: v1 is left exactly as it shipped, and anything that becomes obsolete
// afterwards is undone by a later version rather than by editing history.
const schemaVersion = 3

type Store struct{ db *sql.DB }

// Open creates the database with 0600 permissions and applies migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)",
		strings.ReplaceAll(path, string(filepath.Separator), "/"))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A panel is a single-writer workload; one connection also removes any chance
	// of "database is locked" races between the HTTP handlers and the scheduler.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	st := &Store{db: db}
	if err := st.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// sqlite creates its files with the process umask, which on a default host is
	// 022 -> world-readable. This file holds password hashes, session ids and the
	// audit trail, so tighten it here rather than trusting whoever installed us.
	// The -wal and -shm siblings hold the same bytes until the next checkpoint.
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if fi, err := os.Stat(f); err == nil && fi.Mode().Perm() != 0o600 {
			if err := os.Chmod(f, 0o600); err != nil {
				db.Close()
				return nil, fmt.Errorf("chmod %s: %w", filepath.Base(f), err)
			}
		}
	}
	return st, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_meta(
		key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	var ver int
	row := s.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key='version'`)
	if err := row.Scan(&ver); err != nil {
		ver = 0
	}
	if ver > schemaVersion {
		return fmt.Errorf("database schema v%d is newer than this binary (v%d); refuse to downgrade", ver, schemaVersion)
	}
	for v := ver + 1; v <= schemaVersion; v++ {
		if err := s.apply(v); err != nil {
			return fmt.Errorf("migration %d: %w", v, err)
		}
	}
	_, err := s.db.Exec(`INSERT INTO schema_meta(key,value) VALUES('version',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(schemaVersion))
	return err
}

func (s *Store) apply(v int) error {
	switch v {
	case 1:
		const ddl = `
CREATE TABLE users(
  id             INTEGER PRIMARY KEY,
  username       TEXT NOT NULL UNIQUE,
  pw_hash        TEXT NOT NULL,
  totp_secret    TEXT NOT NULL DEFAULT '',
  totp_enabled   INTEGER NOT NULL DEFAULT 0,
  must_change_pw INTEGER NOT NULL DEFAULT 0,
  pw_updated_at  INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER NOT NULL DEFAULT 0,
  last_login_ip  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE sessions(
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  ua         TEXT NOT NULL DEFAULT '',
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_exp ON sessions(expires_at);

-- Login failures are counted per IP by sec.RateLimiter; the table keeps the
-- forensic trail the UI shows (success/failure, source, user agent).
CREATE TABLE login_events(
  id        INTEGER PRIMARY KEY,
  at        INTEGER NOT NULL,
  ip        TEXT NOT NULL,
  username  TEXT NOT NULL,
  ok        INTEGER NOT NULL,
  reason    TEXT NOT NULL DEFAULT '',
  ua        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_login_ip_time ON login_events(ip, at);

-- Audit rows are append-only by API contract: there is no DELETE endpoint and
-- the only removal path is a dated archive export. BaoTa offers "清空日志"; an
-- admin panel that lets the audited party erase the audit trail is not an audit
-- trail.
CREATE TABLE audit(
  id          INTEGER PRIMARY KEY,
  at          INTEGER NOT NULL,
  user        TEXT NOT NULL,
  ip          TEXT NOT NULL,
  geo         TEXT NOT NULL DEFAULT '',
  action      TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  params_hash TEXT NOT NULL DEFAULT '',
  params_mask TEXT NOT NULL DEFAULT '',
  result      TEXT NOT NULL DEFAULT 'ok',
  error       TEXT NOT NULL DEFAULT '',
  duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_audit_time ON audit(at DESC);

-- Typed settings, one row each, validated in Go. Replaces *.pl flag files.
CREATE TABLE settings(
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
`
		if _, err := s.db.Exec(ddl); err != nil {
			return err
		}
		now := time.Now().Unix()
		for _, seed := range []struct{ k, v string }{
			{"panel.port", "29080"},
			{"panel.entrance", ""},
			{"panel.ssl", "true"},
			{"panel.session_timeout", "43200"},
			{"panel.login_limit", "5"},
			{"panel.unauth_status", "404"},
			{"panel.basic_auth", "false"},
			{"panel.ip_allowlist", ""},
			{"panel.password_expiry_days", "0"},
			{"panel.trust_proxy", "false"},
			{"panel.created_at", fmt.Sprint(now)},
		} {
			if _, err := s.db.Exec(`INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)`,
				seed.k, seed.v, now); err != nil {
				return err
			}
		}
		return nil
	case 2:
		// panel.basic_auth was seeded by v1 but never had an enforcement point,
		// and a second authentication channel is not something this panel wants
		// to grow: identity stays "one administrator + session + TOTP + IP
		// allowlist + CSRF + lockout". The key is gone from the editable list
		// (internal/api/system.go) and any row an older binary wrote is removed
		// here. v1's seed list is deliberately left untouched — rewriting a
		// migration that has already run is how a schema stops being traceable.
		_, err := s.db.Exec(`DELETE FROM settings WHERE key='panel.basic_auth'`)
		return err
	case 3:
		// sessions.id is the bearer token: whoever holds it holds the session.
		// The M1 session list has to name rows to the browser without handing
		// them that token, so each row gets a second, non-secret handle.
		//
		// It is a separate column rather than a truncation of the id (showing
		// "a1b2c3…" is how a partial credential ends up copy-pastable), and
		// rather than SQLite's rowid (a rowid survives no VACUUM, so a URL
		// someone bookmarked yesterday can point at a different session after a
		// maintenance run — a revoke-that-hits-the-wrong-row is exactly the
		// failure this panel should not be able to have).
		//
		// Every step below is written to be re-runnable. migrate() only applies
		// versions above the stored one, so in the normal path this runs once;
		// but the ALTER, the backfill and the index are three statements, and a
		// power cut between any two of them would otherwise leave a panel that
		// cannot start again — "duplicate column name" on every boot, with the
		// operator outside their own machine and the fix being manual SQL. A
		// migration that cannot be resumed after a crash is not a migration.
		has, err := s.hasColumn("sessions", "ref")
		if err != nil {
			return err
		}
		if !has {
			if _, err := s.db.Exec(`ALTER TABLE sessions ADD COLUMN ref TEXT NOT NULL DEFAULT ''`); err != nil {
				return fmt.Errorf("add sessions.ref: %w", err)
			}
		}
		// Backfill: rows written before this version get handles too, otherwise
		// an operator looking at the session list after an upgrade sees rows
		// they cannot revoke. hex(randomblob(8)) is evaluated per row, and the
		// loop re-draws any collision instead of trusting one pass to be enough.
		for {
			if _, err := s.db.Exec(`UPDATE sessions
				SET ref=lower(hex(randomblob(8)))
				WHERE ref='' OR ref IN (SELECT ref FROM sessions WHERE ref<>'' GROUP BY ref HAVING COUNT(1)>1)`); err != nil {
				return fmt.Errorf("backfill sessions.ref: %w", err)
			}
			var dup int
			if err := s.db.QueryRow(`SELECT COUNT(1) FROM (SELECT ref FROM sessions
				WHERE ref<>'' GROUP BY ref HAVING COUNT(1)>1)`).Scan(&dup); err != nil {
				return err
			}
			if dup == 0 {
				break
			}
		}
		if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_ref
			ON sessions(ref) WHERE ref<>''`); err != nil {
			return fmt.Errorf("unique index on sessions.ref: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("no migration for version %d", v)
	}
}

// ---- sessions (read side) -------------------------------------------------

// SessionRow is one row of the sessions table as the panel UI needs it.
//
// deliberately absent: the session token. sessions.id is a bearer credential —
// holding it *is* being logged in — and a list endpoint is exactly the place
// where such a value gets screenshotted, logged, or read out of the browser by
// the next XSS. The UI sees Ref instead, which is scoped by user_id on every
// query that uses it.
type SessionRow struct {
	Ref       string
	UserID    int64
	CreatedAt int64
	ExpiresAt int64
	IP        string
	UserAgent string
	Revoked   bool
}

// ListSessions returns the account's own sessions, newest first, revoked rows
// last: the operator asks "which of these is the laptop at home", and a dead row
// still answers that for a while after it dies. limit is clamped, because this
// is a UI list, not an export.
func (s *Store) ListSessions(userID int64, limit int) ([]SessionRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT ref,user_id,created_at,expires_at,ip,ua,revoked
		FROM sessions WHERE user_id=? ORDER BY revoked ASC, created_at DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		var rev int
		if err := rows.Scan(&r.Ref, &r.UserID, &r.CreatedAt, &r.ExpiresAt, &r.IP, &r.UserAgent, &rev); err != nil {
			return nil, err
		}
		r.Revoked = rev != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountSessions reports live (non-revoked, unexpired) sessions for one account.
func (s *Store) CountSessions(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE user_id=? AND revoked=0 AND expires_at>?`,
		userID, time.Now().Unix()).Scan(&n)
	return n, err
}

// RevokeByRef marks one of the account's own sessions dead and reports whether
// anything matched. A ref that belongs to somebody else does not exist here —
// the user_id is in the WHERE clause, so the answer is "no rows", not "yes".
func (s *Store) RevokeByRef(userID int64, ref string) (bool, error) {
	if ref == "" {
		return false, nil
	}
	res, err := s.db.Exec(`UPDATE sessions SET revoked=1 WHERE user_id=? AND ref=? AND revoked=0`,
		userID, ref)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RevokeOthers kills every session of the account except keepRef ("" keeps
// none). Returns how many rows were revoked, which excludes the kept one by
// construction.
func (s *Store) RevokeOthers(userID int64, keepRef string) (int, error) {
	var res sql.Result
	var err error
	if keepRef == "" {
		res, err = s.db.Exec(`UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0`, userID)
	} else {
		res, err = s.db.Exec(`UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0 AND ref<>?`,
			userID, keepRef)
	}
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// RefByID translates a session token into its public handle. The API handlers
// know the token (it is the request's own cookie) and need the handle to say
// "this is the row you are using right now" without comparing tokens in the UI.
func (s *Store) RefByID(id string) (string, bool, error) {
	var ref string
	err := s.db.QueryRow(`SELECT ref FROM sessions WHERE id=?`, id).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return ref, true, nil
}

// ---- settings -------------------------------------------------------------

func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now().Unix())
	return err
}

// ---- users ----------------------------------------------------------------

type User struct {
	ID           int64
	Username     string
	PwHash       string
	TOTPSecret   string
	TOTPEnabled  bool
	MustChangePW bool
	PwUpdatedAt  int64
	CreatedAt    int64
	LastLoginAt  int64
	LastLoginIP  string
}

func (s *Store) UserByUsername(name string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT id,username,pw_hash,totp_secret,totp_enabled,must_change_pw,
		pw_updated_at,created_at,last_login_at,last_login_ip FROM users WHERE username=?`, name).
		Scan(&u.ID, &u.Username, &u.PwHash, &u.TOTPSecret, &u.TOTPEnabled, &u.MustChangePW,
			&u.PwUpdatedAt, &u.CreatedAt, &u.LastLoginAt, &u.LastLoginIP)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) HasAnyUser() (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM users`).Scan(&n)
	return n > 0, err
}

func (s *Store) CreateUser(u *User) error {
	res, err := s.db.Exec(`INSERT INTO users(username,pw_hash,totp_secret,totp_enabled,must_change_pw,pw_updated_at,created_at)
		VALUES(?,?,?,?,?,?,?)`, u.Username, u.PwHash, u.TOTPSecret, b2i(u.TOTPEnabled),
		b2i(u.MustChangePW), u.PwUpdatedAt, u.CreatedAt)
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) SetPassword(userID int64, hash string, mustChange bool) error {
	_, err := s.db.Exec(`UPDATE users SET pw_hash=?, must_change_pw=?, pw_updated_at=? WHERE id=?`,
		hash, b2i(mustChange), time.Now().Unix(), userID)
	return err
}

// SetMustChange raises or clears the "this password has to be replaced before
// the account is usable" marker, without touching the hash. It is what makes an
// expiry policy and a CLI-set password converge on one flag and one gate.
func (s *Store) SetMustChange(userID int64, must bool) error {
	_, err := s.db.Exec(`UPDATE users SET must_change_pw=? WHERE id=?`, b2i(must), userID)
	return err
}

// UserByID is the per-request lookup behind the password gate. It behaves exactly
// like UserByUsername, including returning sql.ErrNoRows, so callers only have to
// learn one error shape. There is one administrator in practice, so an extra
// indexed SELECT costs nothing and beats caching a flag that a CLI command can
// change while the panel is running.
func (s *Store) UserByID(id int64) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT id,username,pw_hash,totp_secret,totp_enabled,must_change_pw,
		pw_updated_at,created_at,last_login_at,last_login_ip FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.PwHash, &u.TOTPSecret, &u.TOTPEnabled, &u.MustChangePW,
			&u.PwUpdatedAt, &u.CreatedAt, &u.LastLoginAt, &u.LastLoginIP)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) SetTOTP(userID int64, secret string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?`,
		secret, b2i(enabled), userID)
	return err
}

func (s *Store) TouchLogin(userID int64, ip string) error {
	_, err := s.db.Exec(`UPDATE users SET last_login_at=?, last_login_ip=? WHERE id=?`,
		time.Now().Unix(), ip, userID)
	return err
}

// hasColumn reports whether a table already has a column. Migration v3 needs it
// to stay re-runnable; nothing else in this package should, and that is the
// reason it is unexported.
func (s *Store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
