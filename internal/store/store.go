// Package store keeps all persistent state in one SQLite file.
//
// Deliberate departure from BaoTa: state is never expressed as "does data/x.pl
// exist". On that panel `data/bind.pl` is a one-byte empty file that reads as
// "account bound" while the UI says the opposite. Every flag here is an explicit
// row with a typed value, created by a versioned migration.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

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
	default:
		return fmt.Errorf("no migration for version %d", v)
	}
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

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
