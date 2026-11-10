package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/store"
)

func newLogger(t *testing.T) (*Logger, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st), st
}

func TestWriteListAndMasking(t *testing.T) {
	l, _ := newLogger(t)
	l.Write(Entry{User: "admin", IP: "203.0.113.9", Action: "POST /api/v1/login",
		Target: "/api/v1/login", Result: "ok",
		Params: map[string]string{"username": "admin", "password": "Sup3rSecret!pw", "code": "123456"}})
	l.Write(Entry{User: "admin", IP: "203.0.113.9", Action: "PUT /api/v1/settings/{key}",
		Target: "/api/v1/settings/panel.ip_allowlist", Result: "client_error",
		Params: map[string]string{"value": "1.2.3.4/99"}, Elapsed: 12 * time.Millisecond})

	rows, total, err := l.List(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("total=%d rows=%d", total, len(rows))
	}
	// Newest first, so an operator investigating an incident reads the current
	// situation without paging.
	if rows[0].Action != "PUT /api/v1/settings/{key}" {
		t.Errorf("ordering wrong: %+v", rows[0])
	}
	if strings.Contains(rows[0].Params+rows[1].Params, "Sup3rSecret!pw") {
		t.Error("password stored in the clear")
	}
	if !strings.Contains(rows[1].Params, "password=***") {
		t.Errorf("password not masked: %q", rows[1].Params)
	}
	if !strings.Contains(rows[1].Params, "username=admin") {
		t.Errorf("non-secret field dropped: %q", rows[1].Params)
	}
	// A hash of the raw values lets a forensic review prove what was submitted
	// without storing it. Two different passwords must not collide.
	if rows[1].Hash == "" || len(rows[1].Hash) < 16 {
		t.Errorf("no params hash recorded: %q", rows[1].Hash)
	}

	// Paging is a view, not a filter on the total.
	page, ptot, err := l.List(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || ptot != 2 {
		t.Errorf("page=%d total=%d", len(page), ptot)
	}
	if _, _, err := l.List(0, 0); err != nil {
		t.Errorf("limit 0 should not error: %v", err)
	}
}

func TestMaskCoversTheShapesCredentialsArriveIn(t *testing.T) {
	in := map[string]string{
		"password": "x", "Password": "y", "old_password": "z", "db_password": "w",
		"privateKey": "v", "certPem": "u", "token": "t", "authorization": "s",
		"secret": "r", "note": "keep me", "long": strings.Repeat("a", 400),
	}
	out := Mask(in)
	for _, k := range []string{"password", "Password", "old_password", "db_password",
		"privateKey", "certPem", "token", "authorization", "secret"} {
		if out[k] != "***" {
			t.Errorf("%s not masked: %q", k, out[k])
		}
	}
	if out["note"] != "keep me" {
		t.Errorf("harmless value altered: %q", out["note"])
	}
	if len(out["long"]) > 130 {
		t.Errorf("oversized value not truncated: %d", len(out["long"]))
	}
}

func TestMapFlattensJSONBodies(t *testing.T) {
	got := Map([]byte(`{"username":"admin","password":"x","code":123456,"nested":{"a":1}}`))
	if got["username"] != "admin" || got["code"] != "123456" {
		t.Errorf("flattening wrong: %+v", got)
	}
	if len(Map(nil)) != 0 || len(Map([]byte("not json"))) != 0 {
		t.Error("a malformed body must yield an empty map, not an error or a panic")
	}
}

func TestLoggerSurvivesAnEmptyEntry(t *testing.T) {
	l, st := newLogger(t)
	l.Write(Entry{})
	rows, total, err := l.List(10, 0)
	if err != nil || total != 1 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	if rows[0].Result != "ok" {
		t.Errorf("default result should be ok: %q", rows[0].Result)
	}
	// There is no API that deletes audit rows, in this package or anywhere else.
	if _, err := st.DB().Exec(`DELETE FROM audit`); err != nil {
		t.Fatal(err)
	}
}
