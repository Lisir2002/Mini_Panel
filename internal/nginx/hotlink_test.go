package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Hotlink protection is a fixed Referer check on a regex location. These tests
// pin the exact block, the two valid_referers forms, the marker round-trip, the
// exclusion with proxy/redirect, rollback, and marker rejection.

func TestHotlinkRendersAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetHotlink("old", true, true)
	if err != nil {
		t.Fatalf("SetHotlink: %v", err)
	}
	if !site.Hotlink || !site.HotlinkAllowEmpty {
		t.Errorf("returned hotlink = %v, %v", site.Hotlink, site.HotlinkAllowEmpty)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("old"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		"location ~* " + hotlinkExtensionPattern + " {",
		"valid_referers none blocked server_names;",
		"if ($invalid_referer) {",
		"return 403;",
		`"hotlink":true`,
		`"hotlink_allow_empty":true`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("hotlink config missing %q\n%s", want, body)
		}
	}
	for _, unwanted := range []string{".php|", ".html|", "valid_referers none blocked server_names extra;"} {
		if strings.Contains(string(body), unwanted) {
			t.Errorf("hotlink config contains %q\n%s", unwanted, body)
		}
	}
	if !strings.Contains(string(body), "try_files $uri $uri/ =404;") {
		t.Errorf("hotlink replaced the default location / fallback\n%s", body)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if !list[0].Hotlink || !list[0].HotlinkAllowEmpty {
		t.Errorf("marker round-trip hotlink = %+v", list[0])
	}

	if _, err := m.SetHotlink("old", true, false); err != nil {
		t.Fatalf("disable allow-empty: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if !strings.Contains(string(body), "valid_referers server_names;") {
		t.Errorf("strict hotlink did not drop none/blocked\n%s", body)
	}
	if strings.Contains(string(body), "none blocked server_names") {
		t.Errorf("strict hotlink still allows a missing Referer\n%s", body)
	}

	if _, err := m.SetHotlink("old", false, true); err != nil {
		t.Fatalf("disable hotlink: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if strings.Contains(string(body), "valid_referers") || strings.Contains(string(body), `"hotlink":true`) {
		t.Errorf("disabled hotlink left a block or marker field behind\n%s", body)
	}
	list, _ = m.List()
	if len(list) != 1 || list[0].Hotlink || list[0].HotlinkAllowEmpty {
		t.Errorf("marker after disabling hotlink = %+v", list)
	}
}

func TestHotlinkExcludesProxyAndRedirect(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetHotlink("old", true, true); err != nil {
		t.Fatalf("SetHotlink: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if _, err := m.SetProxy("old", "http://127.0.0.1:3000", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("proxy over hotlink err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetRedirect("old", "https://new.example.com", 301, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("redirect over hotlink err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("rejected proxy/redirect changed the hotlink config\nbefore:\n%s\nafter:\n%s", before, after)
	}

	if _, err := m.SetHotlink("old", false, false); err != nil {
		t.Fatalf("disable hotlink: %v", err)
	}
	if _, err := m.SetProxy("old", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("proxy after disabling hotlink: %v", err)
	}
	before, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if _, err := m.SetHotlink("old", true, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hotlink over proxy err = %v, want ErrInvalid", err)
	}
	after, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("rejected hotlink changed the proxy config\nbefore:\n%s\nafter:\n%s", before, after)
	}

	if _, err := m.SetProxy("old", "", false); err != nil {
		t.Fatalf("clear proxy: %v", err)
	}
	if _, err := m.SetRedirect("old", "https://new.example.com", 301, false); err != nil {
		t.Fatalf("redirect after clearing proxy: %v", err)
	}
	before, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if _, err := m.SetHotlink("old", true, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hotlink over redirect err = %v, want ErrInvalid", err)
	}
	after, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("rejected hotlink changed the redirect config\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestSetHotlinkRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetHotlink("old", true, true); err != nil {
		t.Fatalf("SetHotlink: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	rec.failOn = "-t"
	if _, err := m.SetHotlink("old", true, false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetHotlink err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("failed hotlink change was not rolled back\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || !list[0].Hotlink || !list[0].HotlinkAllowEmpty {
		t.Errorf("marker after rollback = %+v", list)
	}
}

func TestMarkerRejectsHotlinkWithProxyOrRedirect(t *testing.T) {
	cases := []string{
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","hotlink":true,"proxy_target":"http://127.0.0.1:3000"}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","hotlink":true,"redirect_target":"https://new.example.com","redirect_code":301}`,
	}
	for _, marker := range cases {
		m, _ := newTestManager(t)
		body := headerLine + "\n" + markerLine + marker + "\n"
		if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("old")), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		list, err := m.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 0 {
			t.Errorf("invalid hotlink marker listed as a panel site: %s", marker)
		}
	}

	// allow_empty without hotlink is normalized instead of being rejected: it
	// cannot change what nginx serves, and older markers must stay readable.
	m, _ := newTestManager(t)
	body := headerLine + "\n" + markerLine +
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","hotlink_allow_empty":true}` + "\n"
	if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("old")), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].Hotlink || list[0].HotlinkAllowEmpty {
		t.Errorf("allow_empty without hotlink was not normalized: %+v", list[0])
	}
}
