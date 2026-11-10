package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "minipanel.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestMigrationsAreIdempotentAndSeeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minipanel.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := st.migrate(); err != nil {
		t.Fatalf("third migrate: %v", err)
	}
	var ver int
	if err := st.DB().QueryRow(`SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key='version'`).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != schemaVersion {
		t.Errorf("schema version %d, want %d", ver, schemaVersion)
	}
	// Every setting the API exposes must exist as a typed row: no *.pl files, and
	// no row the UI has to invent a default for.
	for _, k := range []string{"panel.port", "panel.entrance", "panel.ssl", "panel.session_timeout",
		"panel.login_limit", "panel.unauth_status", "panel.basic_auth", "panel.ip_allowlist",
		"panel.password_expiry_days", "panel.trust_proxy", "panel.created_at"} {
		if _, err := st.GetSetting(k); err != nil {
			t.Errorf("seed row %s missing: %v", k, err)
		}
	}
	// Re-opening a database must not duplicate or reset anything.
	if err := st.SetSetting("panel.ip_allowlist", "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if v, _ := st2.GetSetting("panel.ip_allowlist"); v != "203.0.113.7" {
		t.Errorf("value lost across reopen: %q", v)
	}
	st2.Close()

	// Opening a database written by a newer binary must refuse, not downgrade.
	if err := downgrade(path); err == nil {
		t.Fatal("refused to open a newer schema")
	}
}

func downgrade(path string) error {
	st, err := Open(path)
	if err != nil {
		return err
	}
	if _, err := st.DB().Exec(`UPDATE schema_meta SET value='999' WHERE key='version'`); err != nil {
		st.Close()
		return err
	}
	st.Close()
	_, err = Open(path)
	return err
}

func TestUserLifecycle(t *testing.T) {
	st := open(t)
	if has, err := st.HasAnyUser(); err != nil || has {
		t.Fatalf("fresh database already has users: %v %v", has, err)
	}
	now := time.Now().Unix()
	u := &User{Username: "admin", PwHash: "$2a$12$placeholder", CreatedAt: now, PwUpdatedAt: now}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 {
		t.Error("no id assigned")
	}
	if err := st.CreateUser(&User{Username: "admin", PwHash: "x", CreatedAt: now}); err == nil {
		t.Error("duplicate username accepted")
	}
	got, err := st.UserByUsername("admin")
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPEnabled || got.MustChangePW {
		t.Errorf("new user should have 2FA off: %+v", got)
	}
	if err := st.SetPassword(u.ID, "hash2", true); err != nil {
		t.Fatal(err)
	}
	got, _ = st.UserByUsername("admin")
	if got.PwHash != "hash2" || !got.MustChangePW {
		t.Errorf("password update not persisted: %+v", got)
	}
	if err := st.SetTOTP(u.ID, "SECRET", true); err != nil {
		t.Fatal(err)
	}
	got, _ = st.UserByUsername("admin")
	if got.TOTPSecret != "SECRET" || !got.TOTPEnabled {
		t.Errorf("totp update not persisted: %+v", got)
	}
	if _, err := st.UserByUsername("ghost"); err == nil {
		t.Error("missing user returned no error")
	}
	if err := st.TouchLogin(u.ID, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.UserByUsername("admin")
	if got.LastLoginIP != "203.0.113.9" || got.LastLoginAt == 0 {
		t.Errorf("login not recorded: %+v", got)
	}
}

func TestFilePermissionsAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minipanel.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// The database holds password hashes and session ids.
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("db is readable by others: %v", fi.Mode())
	}
}
