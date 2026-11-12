package nginx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newConfDManager builds a conf.d-only layout: no sites-available/enabled
// pair, one wildcard include, so the parking-directory mechanism is the one
// under test.
func newConfDManager(t *testing.T) (*Manager, *recorder) {
	t.Helper()
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "nginx.conf"),
		[]byte("http {\n    include conf.d/*.conf;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := New(base, filepath.Join(base, "www"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Layout.Mode != ModeConfD {
		t.Fatalf("layout mode = %v, want conf.d", m.Layout.Mode)
	}
	rec := &recorder{}
	m.Run = rec.run
	return m, rec
}

func TestSetEnabledSitesLayoutTogglesSymlink(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	conf := m.Layout.ConfigPath("blog")
	link := m.Layout.LinkPath("blog")

	rec.cmds = nil
	s, err := m.SetEnabled("blog", false)
	if err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if s.Enabled {
		t.Error("returned site still enabled")
	}
	if want := "nginx -t|nginx -s reload"; strings.Join(rec.cmds, "|") != want {
		t.Errorf("commands = %v, want %s", rec.cmds, want)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("symlink still present after stop: %v", err)
	}
	if _, err := os.Stat(conf); err != nil {
		t.Errorf("vhost file must not move in sites layout: %v", err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].Enabled {
		t.Fatalf("List after stop = %+v, %v; want one disabled site", list, err)
	}

	rec.cmds = nil
	s, err = m.SetEnabled("blog", true)
	if err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if !s.Enabled {
		t.Error("returned site not enabled")
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("symlink not recreated: %v", err)
	}
	if target != "../sites-available/"+FileName("blog") {
		t.Errorf("symlink target = %q", target)
	}
	if want := "nginx -t|nginx -s reload"; strings.Join(rec.cmds, "|") != want {
		t.Errorf("commands = %v, want %s", rec.cmds, want)
	}
}

func TestSetEnabledIdempotentRunsNoCommand(t *testing.T) {
	for _, mode := range []string{"sites", "confd"} {
		t.Run(mode, func(t *testing.T) {
			var m *Manager
			var rec *recorder
			if mode == "sites" {
				m, rec = newTestManager(t)
			} else {
				m, rec = newConfDManager(t)
			}
			if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			rec.cmds = nil
			if _, err := m.SetEnabled("blog", true); err != nil {
				t.Fatalf("SetEnabled(true) on enabled site: %v", err)
			}
			if len(rec.cmds) != 0 {
				t.Errorf("no-op switch ran commands: %v", rec.cmds)
			}
			if _, err := m.SetEnabled("blog", false); err != nil {
				t.Fatalf("SetEnabled(false): %v", err)
			}
			rec.cmds = nil
			if _, err := m.SetEnabled("blog", false); err != nil {
				t.Fatalf("SetEnabled(false) on stopped site: %v", err)
			}
			if len(rec.cmds) != 0 {
				t.Errorf("second stop ran commands: %v", rec.cmds)
			}
		})
	}
}

func TestSetEnabledRestoresLinkWhenTestFails(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	link := m.Layout.LinkPath("blog")
	rec.failOn = "-t"
	if _, err := m.SetEnabled("blog", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("SetEnabled error = %v, want ErrConfigRejected", err)
	}
	if _, err := os.Readlink(link); err != nil {
		t.Errorf("symlink not restored after failed stop: %v", err)
	}
	list, _ := m.List()
	if len(list) != 1 || !list[0].Enabled {
		t.Fatalf("site must remain enabled after failed stop: %+v", list)
	}

	// Now stop for real, then fail the enable: the link must stay gone.
	rec.failOn = ""
	if _, err := m.SetEnabled("blog", false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	rec.failOn = "reload"
	if _, err := m.SetEnabled("blog", true); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("SetEnabled(true) error = %v, want ErrConfigRejected", err)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("symlink must be removed again after failed enable: %v", err)
	}
}

func TestSetEnabledConfDMovesFileAndBack(t *testing.T) {
	m, rec := newConfDManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	active := m.Layout.ConfigPath("blog")
	parked := filepath.Join(m.Layout.DisabledDir(), FileName("blog"))
	body, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}

	rec.cmds = nil
	s, err := m.SetEnabled("blog", false)
	if err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if s.Enabled || s.ConfigPath != parked {
		t.Errorf("stopped site = enabled:%v path:%s, want disabled at %s", s.Enabled, s.ConfigPath, parked)
	}
	if want := "nginx -t|nginx -s reload"; strings.Join(rec.cmds, "|") != want {
		t.Errorf("commands = %v, want %s", rec.cmds, want)
	}
	if _, err := os.Stat(active); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("active file still present: %v", err)
	}
	got, err := os.ReadFile(parked)
	if err != nil || string(got) != string(body) {
		t.Errorf("parked bytes differ or missing: %v", err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].Enabled || list[0].ConfigPath != parked {
		t.Fatalf("List after stop = %+v, %v", list, err)
	}

	if _, err := m.SetEnabled("blog", true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if _, err := os.Stat(parked); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("parked file still present after enable: %v", err)
	}
	got, err = os.ReadFile(active)
	if err != nil || string(got) != string(body) {
		t.Errorf("restored bytes differ or missing: %v", err)
	}
	list, _ = m.List()
	if len(list) != 1 || !list[0].Enabled {
		t.Fatalf("List after enable = %+v", list)
	}
}

func TestSetEnabledConfDRestoresWhenTestFails(t *testing.T) {
	m, rec := newConfDManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	active := m.Layout.ConfigPath("blog")
	rec.failOn = "-t"
	if _, err := m.SetEnabled("blog", false); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("error = %v, want ErrConfigRejected", err)
	}
	if _, err := os.Stat(active); err != nil {
		t.Errorf("file not moved back after failed stop: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.Layout.DisabledDir(), FileName("blog"))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("parked residue after failed stop: %v", err)
	}
	list, _ := m.List()
	if len(list) != 1 || !list[0].Enabled {
		t.Fatalf("site must remain enabled: %+v", list)
	}
}

func TestSetEnabledForeignAndMissing(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.SetEnabled("ghost", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site error = %v, want ErrNotFound", err)
	}
	if _, err := m.SetEnabled("../evil", false); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid name error = %v, want ErrInvalid", err)
	}
	// A foreign file matching the name pattern is not the panel's to stop.
	foreign := filepath.Join(m.Layout.Dir(), FileName("foreign"))
	if err := os.WriteFile(foreign, []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetEnabled("foreign", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign site error = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign file touched: %v", err)
	}
}

func TestDeleteStoppedConfDSiteRemovesParkedFile(t *testing.T) {
	m, _ := newConfDManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetEnabled("blog", false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	parked := filepath.Join(m.Layout.DisabledDir(), FileName("blog"))
	if _, err := m.Delete("blog"); err != nil {
		t.Fatalf("Delete stopped site: %v", err)
	}
	if _, err := os.Stat(parked); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("parked file survived delete: %v", err)
	}
	list, _ := m.List()
	if len(list) != 0 {
		t.Fatalf("List after delete = %+v, want empty", list)
	}
}

func TestCreateRefusesNameHeldByStoppedConfDSite(t *testing.T) {
	m, _ := newConfDManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetEnabled("blog", false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"other.example.com"}}); !errors.Is(err, ErrExists) {
		t.Fatalf("Create over stopped name = %v, want ErrExists", err)
	}
	// The parked configuration must be untouched by the refused create.
	if _, err := os.Stat(filepath.Join(m.Layout.DisabledDir(), FileName("blog"))); err != nil {
		t.Errorf("parked file damaged: %v", err)
	}
}

func TestFeatureWriteOnStoppedConfDSiteTargetsParkedPath(t *testing.T) {
	m, _ := newConfDManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetEnabled("blog", false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	parked := filepath.Join(m.Layout.DisabledDir(), FileName("blog"))
	if _, err := m.SetAutoIndex("blog", true); err != nil {
		t.Fatalf("SetAutoIndex on stopped site: %v", err)
	}
	b, err := os.ReadFile(parked)
	if err != nil || !strings.Contains(string(b), "autoindex on;") {
		t.Errorf("edit did not land in parked file: %v\n%s", err, b)
	}
	if _, err := os.Stat(m.Layout.ConfigPath("blog")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("edit resurrected the active file: %v", err)
	}
	s, err := m.SetEnabled("blog", true)
	if err != nil || !s.Enabled || !s.AutoIndex {
		t.Fatalf("enable after edit = %+v, %v", s, err)
	}
}
