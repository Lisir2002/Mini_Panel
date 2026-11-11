package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rewrite library is a closed vocabulary in the binary. These tests pin the
// three properties that make it safe: only known ids are written, PHP-dependent
// templates cannot land on a static site, and every change still goes through
// test-before-reload with the previous bytes restored on failure.

func TestRewritePresetsAreClosedAndStable(t *testing.T) {
	presets := RewritePresets()
	if len(presets) < 5 {
		t.Fatalf("preset list = %d, want at least the shipped set", len(presets))
	}
	seen := map[string]bool{}
	phpRequired := map[string]bool{}
	for _, p := range presets {
		if p.ID == "" || p.Label == "" || p.Description == "" {
			t.Errorf("preset has an empty field: %+v", p)
		}
		if seen[p.ID] {
			t.Errorf("duplicate preset id %q", p.ID)
		}
		seen[p.ID] = true
		phpRequired[p.ID] = p.RequiresPHP
	}
	for _, want := range []string{"none", "wordpress", "laravel", "thinkphp", "spa"} {
		if !seen[want] {
			t.Errorf("preset %q missing", want)
		}
	}
	if phpRequired["wordpress"] != true || phpRequired["laravel"] != true || phpRequired["thinkphp"] != true {
		t.Errorf("PHP templates must be marked requires_php: %+v", phpRequired)
	}
	if phpRequired["none"] || phpRequired["spa"] {
		t.Errorf("static templates must not require PHP: %+v", phpRequired)
	}

	presets[0].Label = "mutated"
	if fresh := RewritePresets(); fresh[0].Label == "mutated" {
		t.Error("RewritePresets returns the package slice instead of a copy")
	}
}

func TestRewriteLocationIsExact(t *testing.T) {
	cases := map[string]string{
		"":          "try_files $uri $uri/ =404;",
		"none":      "try_files $uri $uri/ =404;",
		"wordpress": "try_files $uri $uri/ /index.php?$args;",
		"laravel":   "try_files $uri $uri/ /index.php?$query_string;",
		"thinkphp":  "try_files $uri $uri/ /index.php?s=$uri&$args;",
		"spa":       "try_files $uri $uri/ /index.html;",
	}
	for id, want := range cases {
		if got := rewriteLocation(Site{Rewrite: id}); got != want {
			t.Errorf("rewriteLocation(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestCreateWithRewriteRendersAndRoundTrips(t *testing.T) {
	m, _ := newTestManager(t)
	site, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"}, Rewrite: "wordpress",
		PHPVersion: "8.3", PHPSocket: "/run/php/php8.3-fpm.sock",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if site.Rewrite != "wordpress" {
		t.Errorf("site rewrite = %q, want wordpress", site.Rewrite)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(body), "try_files $uri $uri/ /index.php?$args;") {
		t.Errorf("WordPress fallback missing\n%s", body)
	}
	if !strings.Contains(string(body), `"rewrite":"wordpress"`) {
		t.Errorf("marker did not persist the preset\n%s", body)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].Rewrite != "wordpress" {
		t.Errorf("marker round-trip rewrite = %q", list[0].Rewrite)
	}

	if _, err := m.Create(Spec{
		Name: "app", Domains: []string{"app.example.com"}, Rewrite: "spa",
	}); err != nil {
		t.Fatalf("Create static SPA: %v", err)
	}
	body, err = os.ReadFile(m.Layout.ConfigPath("app"))
	if err != nil {
		t.Fatalf("read SPA config: %v", err)
	}
	if !strings.Contains(string(body), "try_files $uri $uri/ /index.html;") {
		t.Errorf("SPA fallback missing\n%s", body)
	}
}

func TestRewriteRequiresPHPAndAReversibleUnbind(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{
		Name: "static", Domains: []string{"static.example.com"}, Rewrite: "wordpress",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("static site accepted a PHP rewrite: %v", err)
	}
	if _, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"}, Rewrite: "wordpress",
		PHPVersion: "8.3", PHPSocket: "/run/php/php8.3-fpm.sock",
	}); err != nil {
		t.Fatalf("Create PHP site: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if _, err := m.SetPHP("blog", "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("clearing PHP under a PHP rewrite err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("refused unbind changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := m.SetRewrite("blog", "none"); err != nil {
		t.Fatalf("reset rewrite: %v", err)
	}
	if _, err := m.SetPHP("blog", "", ""); err != nil {
		t.Fatalf("unbind after reset: %v", err)
	}
	if _, err := m.SetRewrite("blog", "wordpress"); !errors.Is(err, ErrInvalid) {
		t.Errorf("static site accepted wordpress: %v", err)
	}
	if _, err := m.SetRewrite("blog", "not-a-template"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown template accepted: %v", err)
	}
}

func TestSetRewriteUpdatesAndRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"}, Rewrite: "none",
		PHPVersion: "8.3", PHPSocket: "/run/php/php8.3-fpm.sock",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetRewrite("blog", "laravel")
	if err != nil {
		t.Fatalf("SetRewrite: %v", err)
	}
	if site.Rewrite != "laravel" {
		t.Errorf("returned rewrite = %q", site.Rewrite)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if !strings.Contains(string(body), "try_files $uri $uri/ /index.php?$query_string;") {
		t.Errorf("Laravel fallback missing\n%s", body)
	}

	before := body
	rec.failOn = "-t"
	if _, err := m.SetRewrite("blog", "thinkphp"); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("failed SetRewrite err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("failed rewrite changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].Rewrite != "laravel" {
		t.Errorf("marker after rollback = %+v, want laravel", list)
	}
}

func TestMarkerRejectsUnknownRewrite(t *testing.T) {
	m, _ := newTestManager(t)
	body := headerLine + "\n" + markerLine +
		`{"name":"blog","domains":["blog.example.com"],"root":"/tmp/blog","created_at":"2026-01-01T00:00:00Z","rewrite":"from-a-future-version"}` + "\n"
	if err := os.WriteFile(filepath.Join(m.Layout.Dir(), FileName("blog")), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("marker with unknown rewrite was listed as a panel site: %+v", list)
	}
}
