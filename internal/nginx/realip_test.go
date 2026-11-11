package nginx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real-IP resolution is a server-level block gated by an explicit trust list.
// These tests pin the exact directives, the two header forms, the canonical
// marker round-trip, validation (including refusing trust-everything), rollback,
// and marker rejection.

func TestSetRealIPWritesDirectivesAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetRealIP("old", []string{"10.0.0.0/8", "192.0.2.7", "10.0.0.0/8"}, "")
	if err != nil {
		t.Fatalf("SetRealIP: %v", err)
	}
	if site.RealIPHeader != realIPHeaderXFF {
		t.Errorf("header = %q, want %q", site.RealIPHeader, realIPHeaderXFF)
	}
	if len(site.RealIPFrom) != 2 {
		t.Errorf("trusted sources = %v, want two after dedupe", site.RealIPFrom)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("old"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		"set_real_ip_from 10.0.0.0/8;",
		"set_real_ip_from 192.0.2.7;",
		"real_ip_header X-Forwarded-For;",
		"real_ip_recursive on;",
		`"real_ip_from":["10.0.0.0/8","192.0.2.7"]`,
		`"real_ip_header":"X-Forwarded-For"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("real-IP config missing %q\n%s", want, body)
		}
	}
	if strings.Count(string(body), "set_real_ip_from 10.0.0.0/8;") != 1 {
		t.Errorf("duplicate trusted source was written twice\n%s", body)
	}
	if !strings.Contains(string(body), "location / {") {
		t.Errorf("real-IP directives damaged the location block\n%s", body)
	}

	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if len(list[0].RealIPFrom) != 2 || list[0].RealIPHeader != realIPHeaderXFF {
		t.Errorf("marker round-trip = %+v", list[0])
	}

	// X-Real-IP carries a single address, not a chain, so recursive must not be
	// rendered even though the trust list stays the same.
	if _, err := m.SetRealIP("old", []string{"10.0.0.0/8"}, "x-real-ip"); err != nil {
		t.Fatalf("switch header: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if !strings.Contains(string(body), "real_ip_header X-Real-IP;") {
		t.Errorf("protocol header not canonicalized\n%s", body)
	}
	if strings.Contains(string(body), "real_ip_recursive on;") {
		t.Errorf("X-Real-IP rendered a recursive switch that nginx ignores\n%s", body)
	}

	if _, err := m.SetRealIP("old", nil, ""); err != nil {
		t.Fatalf("clear real IP: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("old"))
	if strings.Contains(string(body), "set_real_ip_from") || strings.Contains(string(body), "real_ip_header") {
		t.Errorf("clearing real IP left directives behind\n%s", body)
	}
	list, _ = m.List()
	if len(list) != 1 || len(list[0].RealIPFrom) != 0 || list[0].RealIPHeader != "" {
		t.Errorf("marker after clearing = %+v", list)
	}
}

func TestRealIPIsValidated(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	rec.cmds = nil
	many := make([]string, 0, maxRealIPSources+1)
	for i := 0; i <= maxRealIPSources; i++ {
		many = append(many, fmt.Sprintf("10.0.%d.1/32", i))
	}
	cases := []struct {
		name   string
		from   []string
		header string
	}{
		{"header without trust", nil, "X-Forwarded-For"},
		{"unknown header", []string{"10.0.0.0/8"}, "X-Forwarded-Host"},
		{"trust everything v4", []string{"0.0.0.0/0"}, ""},
		{"trust everything v6", []string{"::/0"}, ""},
		{"bad prefix", []string{"10.0.0.0/33"}, ""},
		{"not an address", []string{"cdn.example.com"}, ""},
		{"unspecified address", []string{"0.0.0.0"}, ""},
		{"empty entry", []string{""}, ""},
		{"too many", many, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := m.SetRealIP("old", c.from, c.header); !errors.Is(err, ErrInvalid) {
				t.Fatalf("SetRealIP(%v, %q) err = %v, want ErrInvalid", c.from, c.header, err)
			}
		})
	}
	if len(rec.cmds) != 0 {
		t.Errorf("invalid input ran nginx commands: %v", rec.cmds)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("invalid input changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := m.SetRealIP("missing", []string{"10.0.0.0/8"}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site err = %v, want ErrNotFound", err)
	}
}

func TestSetRealIPRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "old", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetRealIP("old", []string{"10.0.0.0/8"}, ""); err != nil {
		t.Fatalf("SetRealIP: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	rec.failOn = "-t"
	if _, err := m.SetRealIP("old", []string{"192.0.2.0/24"}, "X-Real-IP"); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetRealIP err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("old"))
	if string(after) != string(before) {
		t.Errorf("failed real-IP change was not rolled back\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || len(list[0].RealIPFrom) != 1 || list[0].RealIPFrom[0] != "10.0.0.0/8" || list[0].RealIPHeader != realIPHeaderXFF {
		t.Errorf("marker after rollback = %+v", list)
	}
}

func TestMarkerRejectsBadRealIP(t *testing.T) {
	cases := []string{
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","real_ip_from":["10.0.0.0/8"],"real_ip_header":"X-Forwarded-Host"}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","real_ip_from":["0.0.0.0/0"]}`,
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","real_ip_from":[],"real_ip_header":"X-Real-IP"}`,
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
			t.Errorf("invalid real-IP marker listed as a panel site: %s", marker)
		}
	}

	m, _ := newTestManager(t)
	body := headerLine + "\n" + markerLine +
		`{"name":"old","domains":["old.example.com"],"root":"/tmp/old","created_at":"2026-01-01T00:00:00Z","real_ip_from":["10.0.0.0/8"],"real_ip_header":"x-forwarded-for"}` + "\n"
	if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("old")), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if len(list[0].RealIPFrom) != 1 || list[0].RealIPHeader != realIPHeaderXFF {
		t.Errorf("lowercase header was not canonicalized: %+v", list[0])
	}
}
