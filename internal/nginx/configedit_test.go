package nginx

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The config editor is guarded: panel-owned vhosts only, the ownership marker
// line immutable, and every accepted edit still goes through test-before-
// reload. These tests pin reads, accepted edits, each refusal, rollback and
// ownership.

func TestReadSiteConfigReturnsExactBytes(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cfg, err := m.ReadSiteConfig("shop")
	if err != nil {
		t.Fatalf("ReadSiteConfig: %v", err)
	}
	onDisk, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	if cfg.Content != string(onDisk) || cfg.Path != m.Layout.ConfigPath("shop") || cfg.Name != "shop" {
		t.Errorf("read = %+v, want the exact on-disk bytes", cfg)
	}
	if _, err := m.ReadSiteConfig("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing err = %v, want ErrNotFound", err)
	}
	if _, err := m.ReadSiteConfig("Bad Name"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name err = %v, want ErrInvalid", err)
	}
}

func TestWriteSiteConfigAcceptsEditAndReloads(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cfg, err := m.ReadSiteConfig("shop")
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(cfg.Content, "    location / {",
		"    location = /ping { return 200 \"pong\"; }\n\n    location / {", 1)
	rec.cmds = nil
	got, err := m.WriteSiteConfig("shop", edited)
	if err != nil {
		t.Fatalf("WriteSiteConfig: %v", err)
	}
	if got.Content != edited {
		t.Error("returned content differs from the accepted edit")
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}
	onDisk, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	if string(onDisk) != edited {
		t.Error("accepted edit not on disk")
	}
	// The site is still listed: ownership survived the edit.
	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].Name != "shop" {
		t.Errorf("List after edit = %v, %v", list, err)
	}
	// Saving the identical bytes is a no-op success without a reload.
	rec.cmds = nil
	if _, err := m.WriteSiteConfig("shop", edited); err != nil {
		t.Fatalf("no-change write: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("no-change write ran %v, want nothing", rec.cmds)
	}
}

func TestWriteSiteConfigRefusesMarkerChanges(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cfg, err := m.ReadSiteConfig("shop")
	if err != nil {
		t.Fatal(err)
	}
	marker := markerLines(cfg.Content)[0]
	cases := map[string]string{
		"marker removed":    strings.Replace(cfg.Content, marker+"\n", "", 1),
		"marker edited":     strings.Replace(cfg.Content, marker, strings.Replace(marker, "shop.example.com", "evil.example.com", 1), 1),
		"marker duplicated": cfg.Content + marker + "\n",
		"oversize":          cfg.Content + strings.Repeat("# pad\n", maxConfigBytes/6+1),
		"NUL byte":          cfg.Content + "\x00",
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	for name, content := range cases {
		if _, err := m.WriteSiteConfig("shop", content); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
		after, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
		if string(after) != string(before) {
			t.Errorf("%s: refused write touched the file", name)
		}
	}
}

func TestWriteSiteConfigRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "shop", Domains: []string{"shop.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cfg, err := m.ReadSiteConfig("shop")
	if err != nil {
		t.Fatal(err)
	}
	rec.failOn = "-t"
	if _, err := m.WriteSiteConfig("shop", cfg.Content+"\n# broken\n"); err == nil {
		t.Fatal("write succeeded despite nginx -t failure")
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("shop"))
	if string(after) != cfg.Content {
		t.Error("failed write did not restore the exact bytes")
	}
}

func TestSiteConfigRefusesForeignAndMissing(t *testing.T) {
	m, _ := newTestManager(t)
	foreign := m.Layout.ConfigPath("other")
	content := "server { listen 80; server_name other.example.com; }\n"
	if err := os.WriteFile(foreign, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadSiteConfig("other"); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign read err = %v, want ErrNotFound", err)
	}
	if _, err := m.WriteSiteConfig("other", content); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign write err = %v, want ErrNotFound", err)
	}
	if _, err := m.WriteSiteConfig("missing", "server {}\n"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing write err = %v, want ErrNotFound", err)
	}
	if _, err := m.WriteSiteConfig("Bad Name", "server {}\n"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(foreign)
	if string(after) != content {
		t.Error("foreign vhost was modified")
	}
}
