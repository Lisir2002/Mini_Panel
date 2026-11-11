package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recorder stands in for the nginx binary: it records the exact command
// sequence and can be told to fail at one kind of call. The ordering assertion
// ("test before reload") is the point of the fake, not the output text.
type recorder struct {
	cmds   []string
	failOn string
}

func (r *recorder) run(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, cmd)
	if r.failOn != "" && strings.Contains(cmd, r.failOn) {
		return []byte("nginx: [emerg] simulated failure"), errors.New("exit status 1")
	}
	return []byte("ok"), nil
}

func newTestManager(t *testing.T) (*Manager, *recorder) {
	t.Helper()
	base := t.TempDir()
	for _, d := range []string{"sites-available", "sites-enabled"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m, err := New(base, filepath.Join(base, "www"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := &recorder{}
	m.Run = rec.run
	m.Now = func() time.Time { return time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC) }
	return m, rec
}

func TestCreateWritesConfigAndReloads(t *testing.T) {
	m, rec := newTestManager(t)
	site, err := m.Create(Spec{Name: "blog", Domains: []string{"Example.COM", "www.example.com"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if site.Root != filepath.Join(m.SiteRoot, "blog") {
		t.Errorf("root = %q, want %q", site.Root, filepath.Join(m.SiteRoot, "blog"))
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v (test must precede reload)", rec.cmds, want)
	}

	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	for _, want := range []string{
		"server_name example.com www.example.com;",
		"root " + site.Root + ";",
		"try_files $uri $uri/ =404;",
		markerLine,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("config missing %q\n%s", want, body)
		}
	}

	link := m.Layout.LinkPath("blog")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("symlink not created: %v", err)
	}
	if target != "../sites-available/"+FileName("blog") {
		t.Errorf("symlink target = %q, want relative sites-available path", target)
	}
	if fi, err := os.Stat(site.Root); err != nil || !fi.IsDir() {
		t.Errorf("document root not created: %v", err)
	}

	list, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Name != "blog" || !list[0].Enabled {
		t.Errorf("List = %+v, want one enabled blog", list)
	}
	if list[0].CreatedAt != "2026-11-11T04:00:00Z" {
		t.Errorf("created_at = %q, want injected clock", list[0].CreatedAt)
	}
}

func TestCreateRollsBackWhenTestFails(t *testing.T) {
	m, rec := newTestManager(t)
	rec.failOn = "-t"
	_, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}})
	if !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	if _, err := os.Lstat(m.Layout.ConfigPath("blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config left behind after rollback: %v", err)
	}
	if _, err := os.Lstat(m.Layout.LinkPath("blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("symlink left behind after rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.SiteRoot, "blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("document root created for a rejected site")
	}
	if len(rec.cmds) != 1 || rec.cmds[0] != "nginx -t" {
		t.Errorf("commands = %v, want only the failing test (no reload)", rec.cmds)
	}
}

func TestCreateRollsBackWhenReloadFails(t *testing.T) {
	m, rec := newTestManager(t)
	rec.failOn = "reload"
	_, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}})
	if !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	if _, err := os.Lstat(m.Layout.ConfigPath("blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config left behind after failed reload")
	}
}

func TestDeleteRestoresWhenConfigTestFails(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	rec.failOn = "-t"
	_, err := m.Delete("blog")
	if !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	if _, err := os.Stat(m.Layout.ConfigPath("blog")); err != nil {
		t.Errorf("config not restored: %v", err)
	}
	if _, err := os.Lstat(m.Layout.LinkPath("blog")); err != nil {
		t.Errorf("symlink not restored: %v", err)
	}
	list, _ := m.List()
	if len(list) != 1 {
		t.Errorf("site disappeared from List after failed delete: %+v", list)
	}
}

func TestDeleteRemovesConfigButKeepsDocumentRoot(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.SiteRoot, "blog", "index.html"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Delete("blog"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Lstat(m.Layout.ConfigPath("blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config still present")
	}
	if b, err := os.ReadFile(filepath.Join(m.SiteRoot, "blog", "index.html")); err != nil || string(b) != "hi" {
		t.Errorf("document root data was touched: %v", err)
	}
}

func TestListIgnoresForeignConfigs(t *testing.T) {
	m, _ := newTestManager(t)
	foreign := filepath.Join(m.Layout.Dir(), FileName("handmade"))
	if err := os.WriteFile(foreign, []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file with the marker but a filename that disagrees is also not ours:
	// the delete path would otherwise be fooled by a copy/rename.
	wrongName := filepath.Join(m.Layout.Dir(), FileName("renamed"))
	body := headerLine + "\n" + markerLine +
		`{"name":"original","domains":["x.example.com"],"root":"/tmp/x","created_at":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(wrongName, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("foreign configs listed as panel sites: %+v", list)
	}
	if _, err := m.Delete("handmade"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete(foreign) err = %v, want ErrNotFound", err)
	}
}

func TestCreateRefusesDuplicate(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := m.Create(Spec{Name: "blog", Domains: []string{"other.example.com"}})
	if !errors.Is(err, ErrExists) {
		t.Errorf("second Create err = %v, want ErrExists", err)
	}
}

func TestNamesDomainsAndRootsAreValidated(t *testing.T) {
	m, _ := newTestManager(t)
	for _, bad := range []string{"", "a", "Blog", "-blog", "blog_name", "blog/../x", strings.Repeat("a", 33)} {
		if _, err := m.Create(Spec{Name: bad, Domains: []string{"x.example.com"}}); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q accepted or wrong error: %v", bad, err)
		}
	}
	for _, bad := range []string{"", "http://x.com", "x.com/path", "x", "*.", "a b.com", "x.com:8080"} {
		if _, err := m.Create(Spec{Name: "blog", Domains: []string{bad}}); !errors.Is(err, ErrInvalid) {
			t.Errorf("domain %q accepted or wrong error: %v", bad, err)
		}
	}
	if _, err := m.Create(Spec{Name: "blog", Domains: nil}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty domain list accepted")
	}
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"x.example.com"}, Root: "/etc"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("root outside SiteRoot accepted: %v", err)
	}
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"x.example.com"}, Root: m.SiteRoot + "/../escape"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("traversal root accepted: %v", err)
	}
}

func TestConfDLayoutHasNoSymlink(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := New(base, filepath.Join(base, "www"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := &recorder{}
	m.Run = rec.run
	site, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !site.Enabled {
		t.Error("conf.d site should report enabled")
	}
	if _, err := os.Stat(filepath.Join(base, "conf.d", FileName("blog"))); err != nil {
		t.Errorf("config not in conf.d: %v", err)
	}
	list, _ := m.List()
	if len(list) != 1 || !list[0].Enabled {
		t.Errorf("List = %+v", list)
	}
}
