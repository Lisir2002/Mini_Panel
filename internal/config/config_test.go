package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurationAcceptsBothForms(t *testing.T) {
	for _, tc := range []struct {
		json string
		want time.Duration
	}{
		{`"12h"`, 12 * time.Hour},
		{`"45m"`, 45 * time.Minute},
		{`"3600000000000"`, time.Hour},
		{`""`, 0},
		{`null`, 0},
	} {
		var d Duration
		if err := json.Unmarshal([]byte(tc.json), &d); err != nil {
			t.Fatalf("%s: %v", tc.json, err)
		}
		if d.D() != tc.want {
			t.Errorf("%s parsed to %v, want %v", tc.json, d.D(), tc.want)
		}
	}
	// The failure mode this type exists to prevent: a hand-edited "12h" read as
	// 12 nanoseconds, i.e. a session that expires instantly.
	var d Duration
	if err := json.Unmarshal([]byte(`"not a duration"`), &d); err == nil {
		t.Error("garbage duration accepted")
	}
	b, err := json.Marshal(Duration(90 * time.Minute))
	if err != nil || string(b) != `"1h30m0s"` {
		t.Errorf("marshal = %s (%v)", b, err)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 29080 || !c.TLS || c.UnauthStatus != 404 || c.LoginLimit != 5 || c.DataDir != "" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestSaveAndLoadRoundTripWithPermissions(t *testing.T) {
	dir := t.TempDir()
	c := Default()
	c.DataDir = filepath.Join(dir, "data")
	c.LogDir = filepath.Join(dir, "logs")
	c.Entrance = "/zq4k7m2p"
	c.Hosts = []string{"panel.example.com"}
	c.SessionTTL = Duration(6 * time.Hour)
	if err := c.Save(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	// The file holds the entrance path, so it must not be world-readable.
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("panel.json mode = %v, want 0600", fi.Mode())
	}
	back, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if back.Entrance != c.Entrance || back.Port != c.Port || back.SessionTTL.D() != c.SessionTTL.D() {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if _, err := os.Stat(Path(dir) + ".tmp"); !os.IsNotExist(err) {
		t.Error("temporary file left behind by the atomic write")
	}
}

func TestValidateRejectsNonsenseAndHealsSoftFields(t *testing.T) {
	c := Default()
	c.DataDir = "/tmp/x"
	c.Port = 0
	if err := c.Validate(); err == nil {
		t.Error("port 0 accepted")
	}
	c.Port = 29080
	c.Bind = ""
	if err := c.Validate(); err == nil {
		t.Error("empty bind accepted")
	}
	c.Bind = "0.0.0.0"
	for _, bad := range []int{0, 300, 499, 1000, 99999} {
		c.UnauthStatus = bad
		if err := c.Validate(); err == nil {
			t.Errorf("unauth_status %d accepted", bad)
		}
	}
	// Soft fields heal rather than crash: a 5-second session TTL is a typo, and
	// a panel that locks every request out is worse than one that fixes it.
	c.UnauthStatus = 404
	c.SessionTTL = Duration(5 * time.Second)
	c.LoginLimit = 0
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.SessionTTL.D() != 12*time.Hour || c.LoginLimit != 5 {
		t.Errorf("heal failed: ttl=%v limit=%d", c.SessionTTL.D(), c.LoginLimit)
	}
}

func TestAddr(t *testing.T) {
	c := Default()
	c.Bind, c.Port = "127.0.0.1", 8443
	if c.Addr() != "127.0.0.1:8443" {
		t.Errorf("Addr = %s", c.Addr())
	}
}
