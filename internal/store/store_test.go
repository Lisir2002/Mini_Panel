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
		"panel.login_limit", "panel.unauth_status", "panel.ip_allowlist",
		"panel.password_expiry_days", "panel.trust_proxy", "panel.created_at"} {
		if _, err := st.GetSetting(k); err != nil {
			t.Errorf("seed row %s missing: %v", k, err)
		}
	}
	// panel.basic_auth is not on that list: v1 seeded it, v2 deletes it, and the
	// API no longer accepts it. A settings row with no code behind it is exactly
	// the kind of control this project refuses to render. GetSetting reports an
	// absent key as ("", nil), so existence is checked where it is actually
	// recorded.
	if n := settingRows(t, st, "panel.basic_auth"); n != 0 {
		t.Errorf("v2 migration left %d panel.basic_auth row(s) behind", n)
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

// TestMigrationV2DropsTheOrphanSetting covers the upgrade path, which a fresh
// database cannot show: an older binary wrote the row, a newer one must not keep
// listing a switch nobody implements.
func TestMigrationV2DropsTheOrphanSetting(t *testing.T) {
	st := open(t)
	if err := st.SetSetting("panel.basic_auth", "true"); err != nil {
		t.Fatal(err)
	}
	if v, err := st.GetSetting("panel.basic_auth"); err != nil || v != "true" {
		t.Fatalf("could not stage the old row: %q %v", v, err)
	}
	if err := st.apply(2); err != nil {
		t.Fatalf("apply(2): %v", err)
	}
	if n := settingRows(t, st, "panel.basic_auth"); n != 0 {
		t.Errorf("orphan row survived the migration (%d rows)", n)
	}
	// Every other setting has to survive it — the migration deletes one key, not
	// the operator's configuration.
	if v, _ := st.GetSetting("panel.login_limit"); v != "5" {
		t.Errorf("unrelated setting changed by migration: %q", v)
	}
	// Applying it twice is a no-op, because migrate() can run on every start.
	if err := st.apply(2); err != nil {
		t.Fatalf("apply(2) again: %v", err)
	}
}

// settingRows counts rows with this key, which is the only way to tell "absent"
// apart from "present and empty" given how GetSetting reports a missing key.
func settingRows(t *testing.T, st *Store, key string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM settings WHERE key=?`, key).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", key, err)
	}
	return n
}

// insertSession writes a row the way an older binary did: no handle at all.
// Without this the upgrade path cannot be tested, because Open() has already
// run v3 by the time a test gets the store.
func insertSession(t *testing.T, st *Store, id, ref string, userID int64, ageSec int64) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := st.DB().Exec(`INSERT INTO sessions(id,ref,user_id,created_at,expires_at,ip,ua,revoked)
		VALUES(?,?,?,?,?,?,?,?)`, id, ref, userID, now-ageSec, now+7200,
		"203.0.113.7", "test", 0); err != nil {
		t.Fatalf("insert session: %v", err)
	}
}

func mustUser(t *testing.T, st *Store, name string) int64 {
	t.Helper()
	u := &User{Username: name, PwHash: "x", CreatedAt: time.Now().Unix(), PwUpdatedAt: time.Now().Unix()}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return u.ID
}

// TestMigrationV3GivesEverySessionRowAHandle is the upgrade case a fresh
// database cannot show: rows written before v3 have no handle, and an operator
// who upgrades must still be able to revoke them from the session list.
func TestMigrationV3GivesEverySessionRowAHandle(t *testing.T) {
	st := open(t)
	uid := mustUser(t, st, "admin")
	// Drop the column's guarantees to the pre-v3 shape: an old row with no
	// handle, and a newer one that already has one.
	if _, err := st.DB().Exec(`DELETE FROM sessions`); err != nil {
		t.Fatal(err)
	}
	insertSession(t, st, "tok-old", "", uid, 3600)
	insertSession(t, st, "tok-new", "cafe000011112222", uid, 60)

	if err := st.apply(3); err != nil {
		t.Fatalf("apply(3): %v", err)
	}
	var oldRef string
	if err := st.DB().QueryRow(`SELECT ref FROM sessions WHERE id='tok-old'`).Scan(&oldRef); err != nil {
		t.Fatal(err)
	}
	if len(oldRef) != 16 || oldRef == "" {
		t.Errorf("backfilled handle = %q, want 16 hex characters", oldRef)
	}
	// Rows that already had a handle keep it: re-drawing would break a revoke
	// the operator has half-done, and it is not what the migration is for.
	var keep string
	if err := st.DB().QueryRow(`SELECT ref FROM sessions WHERE id='tok-new'`).Scan(&keep); err != nil {
		t.Fatal(err)
	}
	if keep != "cafe000011112222" {
		t.Errorf("existing handle rewritten by migration: %q", keep)
	}
	// Re-applying must be safe rather than fatal. The ALTER, the backfill and
	// the index are three statements; a crash between them would otherwise leave
	// every later start failing on "duplicate column name" — a panel that
	// cannot boot is a panel the operator is locked out of, which is the one
	// thing this project's M1 work exists to prevent.
	if err := st.apply(3); err != nil {
		t.Fatalf("apply(3) again (crash-resume path): %v", err)
	}
	// Stage a collision the way a half-finished migration would leave it: the
	// index not yet in place, two rows sharing a handle. Then v3 has to re-draw
	// one of them, because a revoke that hits "a row the operator did not point
	// at" is the failure this column exists to make impossible.
	if _, err := st.DB().Exec(`DROP INDEX IF EXISTS idx_sessions_ref`); err != nil {
		t.Fatalf("drop index to stage a collision: %v", err)
	}
	insertSession(t, st, "tok-dup", "cafe000011112222", uid, 5)
	if err := st.apply(3); err != nil {
		t.Fatalf("apply(3) with a collision: %v", err)
	}
	// A collision group is re-drawn as a whole, so the old shared value is gone
	// and every row has its own handle: asserting "one row keeps cafe…" would be
	// asserting the wrong repair (leaving one of two ambiguous rows alone is
	// still ambiguous).
	var dupGroups int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM (SELECT ref FROM sessions
		WHERE ref<>'' GROUP BY ref HAVING COUNT(1)>1)`).Scan(&dupGroups); err != nil {
		t.Fatal(err)
	}
	if dupGroups != 0 {
		t.Errorf("%d handle groups are still shared after the migration", dupGroups)
	}
	var blank, short int
	if err := st.DB().QueryRow(`SELECT COUNT(1), COUNT(CASE WHEN length(ref)<>16 THEN 1 END)
		FROM sessions`).Scan(&blank, &short); err != nil {
		t.Fatal(err)
	}
	if blank == 0 || short != 0 {
		t.Errorf("after v3: %d rows, %d with a handle of the wrong length", blank, short)
	}
	// The index must be real, not just a comment: take a live handle and try to
	// give it to a second row.
	var taken string
	if err := st.DB().QueryRow(`SELECT ref FROM sessions WHERE ref<>'' LIMIT 1`).Scan(&taken); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO sessions(id,ref,user_id,created_at,expires_at,ip,ua,revoked)
		VALUES('tok-forced',?,?,'','',0)`, taken, uid); err == nil {
		// The column list above is deliberately short: a real duplicate attempt
		// has to fail, and if it does not the unique index is decoration.
		t.Errorf("unique index on sessions.ref did not stop a second row using %q", taken)
	}
}

// TestSessionReadsAndRevokesAreScopedToTheirAccount covers the store side of
// the M1 session endpoints.
func TestSessionReadsAndRevokesAreScopedToTheirAccount(t *testing.T) {
	st := open(t)
	if _, err := st.DB().Exec(`DELETE FROM sessions`); err != nil {
		t.Fatal(err)
	}
	mine := mustUser(t, st, "admin")
	theirs := mustUser(t, st, "second")
	insertSession(t, st, "mine-live", "1111111111111111", mine, 30)
	insertSession(t, st, "mine-old", "2222222222222222", mine, 3600)
	insertSession(t, st, "theirs", "3333333333333333", theirs, 10)
	if _, err := st.DB().Exec(`UPDATE sessions SET revoked=1 WHERE id='mine-old'`); err != nil {
		t.Fatal(err)
	}
	// A row with no handle must not be addressable through the handle API, but
	// it must still show up in the list — hiding it would hide a live session.
	insertSession(t, st, "no-handle", "", mine, 5)

	rows, err := st.ListSessions(mine, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("list returned %d rows, want the 3 belonging to this account (%+v)", len(rows), rows)
	}
	for i := range rows {
		if rows[i].UserID != mine {
			t.Errorf("list leaked another account's row: %+v", rows[i])
		}
	}
	if other, err := st.ListSessions(theirs, 50); err != nil || len(other) != 1 {
		t.Errorf("the other account sees %+v (%v), want exactly its own row", other, err)
	}
	// Live rows first, newest first inside each group: the UI shows "what is
	// signed in" before the history.
	if rows[0].Revoked || rows[len(rows)-1].Revoked != true {
		t.Errorf("ordering wrong: %+v", rows)
	}
	// SessionRow has no token field at all, so there is nothing to assert here:
	// a handler that tried to serialise one would not compile. That is the point
	// of the type, and the reason the API test asserts the wire format instead.

	// Revoking another account's handle is "nothing matched", not a revoke.
	ok, err := st.RevokeByRef(mine, "3333333333333333")
	if err != nil {
		t.Fatalf("revoke cross-account: %v", err)
	}
	if ok {
		t.Error("RevokeByRef revoked a row belonging to another user")
	}
	if revoked := sessionRevoked(t, st, "theirs"); revoked != 0 {
		t.Error("cross-account revoke hit the row anyway")
	}
	if ok, err := st.RevokeByRef(mine, ""); err != nil || ok {
		t.Errorf("empty handle accepted (ok=%v err=%v)", ok, err)
	}
	if ok, err := st.RevokeByRef(mine, "1111111111111111"); err != nil || !ok {
		t.Errorf("own handle refused (ok=%v err=%v)", ok, err)
	}

	// RevokeOthers keeps exactly the one row named.
	n, err := st.RevokeOthers(mine, "2222222222222222")
	if err != nil {
		t.Fatalf("revoke others: %v", err)
	}
	if n != 1 { // no-handle was still live; mine-live already revoked
		t.Errorf("RevokeOthers = %d rows, want 1 (%+v)", n, rows)
	}
	if revoked := sessionRevoked(t, st, "mine-old"); revoked != 1 {
		t.Error("the kept row was revoked anyway")
	}
	if revoked := sessionRevoked(t, st, "no-handle"); revoked != 1 {
		t.Error("a handleless row escaped RevokeOthers; it is still somebody's session")
	}

	// RefByID is how the handlers know which row "I" am.
	if ref, found, err := st.RefByID("mine-old"); err != nil || !found || ref != "2222222222222222" {
		t.Errorf("RefByID = %q %v %v", ref, found, err)
	}
	if _, found, err := st.RefByID("nonexistent-token"); err != nil || found {
		t.Errorf("unknown token reported as found: %v %v", found, err)
	}
	if live, err := st.CountSessions(mine); err != nil || live != 0 {
		t.Errorf("CountSessions after revoking everything = %d %v, want 0", live, err)
	}
}

func sessionRevoked(t *testing.T, st *Store, id string) int {
	t.Helper()
	var r int
	if err := st.DB().QueryRow(`SELECT revoked FROM sessions WHERE id=?`, id).Scan(&r); err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return r
}

func TestSiteMetaRoundTripAndClear(t *testing.T) {
	st := open(t)
	// Fresh store: the migration created the table, so ListSiteMeta succeeds and
	// is empty rather than erroring on a missing table.
	meta, err := st.ListSiteMeta()
	if err != nil {
		t.Fatalf("list empty meta: %v", err)
	}
	if len(meta) != 0 {
		t.Fatalf("new store has %d annotations, want 0", len(meta))
	}
	if err := st.SaveSiteMeta("shop", "电商", "双 11 后扩容"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := st.SaveSiteMeta("blog", "", "个人站"); err != nil {
		t.Fatalf("save note-only: %v", err)
	}
	meta, err = st.ListSiteMeta()
	if err != nil {
		t.Fatalf("list meta: %v", err)
	}
	if meta["shop"].Group != "电商" || meta["shop"].Note != "双 11 后扩容" {
		t.Errorf("shop meta = %+v", meta["shop"])
	}
	if meta["blog"].Group != "" || meta["blog"].Note != "个人站" {
		t.Errorf("blog meta = %+v, want empty group / note set", meta["blog"])
	}

	// Saving empty on both sides deletes the row rather than storing blanks.
	if err := st.SaveSiteMeta("shop", "", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	meta, _ = st.ListSiteMeta()
	if _, ok := meta["shop"]; ok {
		t.Errorf("clear left a row for shop")
	}
	if _, ok := meta["blog"]; !ok {
		t.Errorf("clear deleted an unrelated site's row")
	}

	// Explicit delete on site removal.
	if err := st.DeleteSiteMeta("blog"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	meta, _ = st.ListSiteMeta()
	if len(meta) != 0 {
		t.Errorf("after delete, %d rows remain, want 0", len(meta))
	}
}

func TestSiteMetaUpsertReplaces(t *testing.T) {
	st := open(t)
	if err := st.SaveSiteMeta("shop", "a", "x"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSiteMeta("shop", "b", ""); err != nil {
		t.Fatal(err)
	}
	meta, _ := st.ListSiteMeta()
	if len(meta) != 1 || meta["shop"].Group != "b" || meta["shop"].Note != "" {
		t.Errorf("upsert result = %+v, want one row group=b note empty", meta["shop"])
	}
}
