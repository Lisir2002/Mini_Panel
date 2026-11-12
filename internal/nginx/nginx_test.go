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

// TestDeleteRemovesEnabledLinkBeforeTest simulates the real nginx behaviour
// on a sites-available/sites-enabled layout: the wildcard include lists the
// enabled symlink, and nginx -t follows it. A delete that removed the vhost
// but left the link for "after the transaction" made every delete fail with
// open() ENOENT on Ubuntu/Debian hosts (found by the responsive-UI pass,
// which exercised delete against a real nginx 1.18).
func TestDeleteRemovesEnabledLinkBeforeTest(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.Run = func(name string, args ...string) ([]byte, error) {
		if name == "nginx" && len(args) > 0 && args[0] == "-t" {
			ents, err := os.ReadDir(m.Layout.Enabled)
			if err != nil {
				return nil, err
			}
			for _, e := range ents {
				lp := filepath.Join(m.Layout.Enabled, e.Name())
				if fi, err := os.Lstat(lp); err == nil && fi.Mode()&os.ModeSymlink != 0 {
					if _, err := os.Stat(lp); err != nil {
						return []byte("nginx: [emerg] open() \"" + lp + "\" failed (2: No such file or directory)"),
							errors.New("exit status 1")
					}
				}
			}
		}
		return rec.run(name, args...)
	}
	if _, err := m.Delete("blog"); err != nil {
		t.Fatalf("Delete against dangling-link-aware nginx: %v", err)
	}
	if _, err := os.Lstat(m.Layout.LinkPath("blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("enabled symlink still present after delete: %v", err)
	}
	if list, _ := m.List(); len(list) != 0 {
		t.Errorf("site still listed: %+v", list)
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

// TestCreateWithPHPRendersHandlerAndMarker is the shape php-fpm needs: a
// regex location that refuses missing files, the standard fastcgi_params
// include, an explicit SCRIPT_FILENAME, and fastcgi_pass pointing at the
// platform-resolved unix socket. The marker has to round-trip too, because
// List is how the next page load knows which version a site is bound to.
func TestCreateWithPHPRendersHandlerAndMarker(t *testing.T) {
	m, _ := newTestManager(t)
	site, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"},
		PHPVersion: "8.3", PHPSocket: "/run/php/php8.3-fpm.sock",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if site.PHPVersion != "8.3" || site.PHPSocket != "/run/php/php8.3-fpm.sock" {
		t.Errorf("site php fields = %q/%q", site.PHPVersion, site.PHPSocket)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		"index index.php index.html index.htm;",
		`location ~ \.php$ {`,
		"try_files $uri =404;",
		"include fastcgi_params;",
		"fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
		"fastcgi_pass unix:/run/php/php8.3-fpm.sock;",
		`"php_version":"8.3"`,
		`"php_socket":"/run/php/php8.3-fpm.sock"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("config missing %q\n%s", want, body)
		}
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if list[0].PHPVersion != "8.3" || list[0].PHPSocket != "/run/php/php8.3-fpm.sock" {
		t.Errorf("marker did not round-trip php binding: %+v", list[0])
	}
}

func TestSetPHPSwitchesAndClears(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	if _, err := m.SetPHP("blog", "8.2", "/run/php/php8.2-fpm.sock"); err != nil {
		t.Fatalf("SetPHP: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("switch command order = %v, want %v", rec.cmds, want)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if !strings.Contains(string(body), "fastcgi_pass unix:/run/php/php8.2-fpm.sock;") {
		t.Errorf("switch did not rewrite socket\n%s", body)
	}
	if !strings.Contains(string(body), `"php_version":"8.2"`) {
		t.Errorf("switch did not rewrite marker\n%s", body)
	}

	if _, err := m.SetPHP("blog", "", ""); err != nil {
		t.Fatalf("clear SetPHP: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if strings.Contains(string(body), "fastcgi_pass") || strings.Contains(string(body), "index.php") {
		t.Errorf("cleared site still has a PHP handler\n%s", body)
	}
	if !strings.Contains(string(body), "index index.html index.htm;") {
		t.Errorf("static index line not restored\n%s", body)
	}
}

func TestSetPHPRollsBackWhenTestFails(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"},
		PHPVersion: "8.3", PHPSocket: "/run/php/php8.3-fpm.sock",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	rec.failOn = "-t"
	_, err := m.SetPHP("blog", "8.2", "/run/php/php8.2-fpm.sock")
	if !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("SetPHP err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("failed switch changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if len(rec.cmds) != 3 || rec.cmds[2] != "nginx -t" {
		t.Errorf("commands = %v, want create then failing test (no reload)", rec.cmds)
	}
}

func TestPHPBindingIsValidated(t *testing.T) {
	m, _ := newTestManager(t)
	for _, tc := range []struct{ version, socket string }{
		{"8.3", ""},
		{"", "/run/php/php8.3-fpm.sock"},
		{"v8.3", "/run/php/php8.3-fpm.sock"},
		{"8.3", "php8.3-fpm.sock"},
		{"8.3", "/run/php/php8.3-fpm.sock; evil"},
		{"8.3", "/run/php/../php8.3-fpm.sock"},
		{"8.3", "/run/php/php8.3-fpm"},
	} {
		if _, err := m.Create(Spec{
			Name: "blog", Domains: []string{"blog.example.com"},
			PHPVersion: tc.version, PHPSocket: tc.socket,
		}); !errors.Is(err, ErrInvalid) {
			t.Errorf("PHP binding (%q,%q) accepted or wrong error: %v", tc.version, tc.socket, err)
		}
	}
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create static: %v", err)
	}
	if _, err := m.SetPHP("blog", "8.3", "/run/php/php8.3-fpm.sock;include x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("injection socket accepted: %v", err)
	}
}

// TestCreateWithCustomIndexRendersAndRoundTrips pins both halves of the index
// list: nginx sees the operator's order, and the marker lets the next List call
// show the same list. Without the marker round-trip the edit dialog would open
// with an empty list and silently reset the setting on the next save.
func TestCreateWithCustomIndexRendersAndRoundTrips(t *testing.T) {
	m, _ := newTestManager(t)
	site, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com"},
		Index: []string{" home.html ", "index.html"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if want := []string{"home.html", "index.html"}; strings.Join(site.Index, ",") != strings.Join(want, ",") {
		t.Errorf("index = %v, want %v", site.Index, want)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, want := range []string{
		"index home.html index.html;",
		`"index":["home.html","index.html"]`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("config missing %q\n%s", want, body)
		}
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if strings.Join(list[0].Index, ",") != "home.html,index.html" {
		t.Errorf("marker did not round-trip index: %+v", list[0])
	}
}

// TestIndexIsValidated refuses the two ways a "filename" list could become more
// than a list: path syntax (writes outside the root) and a PHP source file on a
// static site (nginx serves it as text). A PHP-bound site may select index.php,
// but unbinding then has to be a separate, explicit edit.
func TestIndexIsValidated(t *testing.T) {
	m, _ := newTestManager(t)
	for _, index := range [][]string{
		{"index.php"},
		{"../index.html"},
		{"a/b.html"},
		{"index.html", "index.html"},
		{"index.html;evil"},
		{strings.Repeat("a", 65) + ".html"},
		make([]string, 11),
	} {
		if _, err := m.Create(Spec{
			Name: "blog", Domains: []string{"blog.example.com"}, Index: index,
		}); !errors.Is(err, ErrInvalid) {
			t.Errorf("index %v accepted or wrong error: %v", index, err)
		}
	}

	if _, err := m.Create(Spec{
		Name: "app", Domains: []string{"app.example.com"},
		PHPVersion: "8.3", PHPSocket: "/run/php/php8.3-fpm.sock",
		Index: []string{"index.php", "index.html"},
	}); err != nil {
		t.Fatalf("Create with index.php and PHP bound: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if _, err := m.SetPHP("app", "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbind with index.php err = %v, want ErrInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if string(before) != string(after) {
		t.Errorf("refused unbind changed the config")
	}
	if _, err := m.SetBasics("app", []string{"app.example.com"}, "", []string{"index.html"}); err != nil {
		t.Fatalf("drop index.php: %v", err)
	}
	if _, err := m.SetPHP("app", "", ""); err != nil {
		t.Fatalf("unbind after index edit: %v", err)
	}
}

// TestSetBasicsReplacesDomainsRootAndIndex covers the successful edit: domains
// are normalized, a missing root is created, an empty root keeps the current
// one, and an empty index restores the built-in list.
func TestSetBasicsReplacesDomainsRootAndIndex(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"old.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	newRoot := filepath.Join(m.SiteRoot, "data")
	site, err := m.SetBasics("blog",
		[]string{"New.Example.COM", "www.new.example.com"}, newRoot,
		[]string{"home.html", "index.html"})
	if err != nil {
		t.Fatalf("SetBasics: %v", err)
	}
	if want := []string{"new.example.com", "www.new.example.com"}; strings.Join(site.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("domains = %v, want %v", site.Domains, want)
	}
	if site.Root != newRoot {
		t.Errorf("root = %q, want %q", site.Root, newRoot)
	}
	if fi, err := os.Stat(newRoot); err != nil || !fi.IsDir() {
		t.Errorf("new root not created: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	for _, want := range []string{
		"server_name new.example.com www.new.example.com;",
		"root " + newRoot + ";",
		"index home.html index.html;",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("config missing %q\n%s", want, body)
		}
	}
	if _, err := os.Stat(filepath.Join(m.SiteRoot, "blog")); err != nil {
		t.Errorf("old document root was removed: %v", err)
	}

	site, err = m.SetBasics("blog", []string{"new.example.com"}, "", nil)
	if err != nil {
		t.Fatalf("SetBasics defaults: %v", err)
	}
	if site.Root != newRoot {
		t.Errorf("empty root changed the root to %q", site.Root)
	}
	if site.Index != nil {
		t.Errorf("empty index did not reset the list: %v", site.Index)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("blog"))
	if !strings.Contains(string(body), "index index.html index.htm;") {
		t.Errorf("default index line not restored\n%s", body)
	}
	list, _ := m.List()
	if len(list) != 1 || strings.Join(list[0].Domains, ",") != "new.example.com" || list[0].Index != nil {
		t.Errorf("List after edit = %+v", list)
	}
}

func TestSetBasicsRollsBackWhenTestFails(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	newRoot := filepath.Join(m.SiteRoot, "rejected")
	rec.cmds = nil
	rec.failOn = "-t"
	_, err := m.SetBasics("blog", []string{"new.example.com"}, newRoot, []string{"home.html"})
	if !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("SetBasics err = %v, want ErrConfigRejected", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("failed edit changed the config\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if _, err := os.Stat(newRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("new document root left behind after rollback: %v", err)
	}
	if want := []string{"nginx -t"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("commands = %v, want only the failing test (no reload)", rec.cmds)
	}
}

// TestSetBasicsChecksCertificateCoverage prevents the state where the vhost
// claims a new server_name while ssl_certificate still holds the old names.
// Narrowing to names the certificate already covers is allowed; adding an
// uncovered name is refused before any file is written.
func TestSetBasicsChecksCertificateCoverage(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{
		Name: "blog", Domains: []string{"blog.example.com", "www.blog.example.com"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetSelfSigned("blog", false); err != nil {
		t.Fatalf("SetSelfSigned: %v", err)
	}
	if _, err := m.SetBasics("blog", []string{"www.blog.example.com"}, "", nil); err != nil {
		t.Fatalf("narrowing to a covered name was refused: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	_, err := m.SetBasics("blog", []string{"www.blog.example.com", "new.example.com"}, "", nil)
	if !errors.Is(err, ErrTLSInvalid) {
		t.Fatalf("uncovered domain err = %v, want ErrTLSInvalid", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(before) != string(after) {
		t.Errorf("refused domain change still rewrote the config")
	}
}
