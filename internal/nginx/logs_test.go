package nginx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 第十八片：按站点日志。渲染必须带上两条固定指令，查看器读的就是渲染写出的
// 那两个路径；迁移只动面板自有 vhost，且整批走一次 test-before-reload。

func TestCreateRendersPerSiteLogDirectives(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatal(err)
	}
	wantAccess := "    access_log " + filepath.Join(m.LogDir, "blog.access.log") + " combined;"
	wantError := "    error_log " + filepath.Join(m.LogDir, "blog.error.log") + ";"
	if !strings.Contains(string(body), wantAccess) || !strings.Contains(string(body), wantError) {
		t.Errorf("vhost missing per-site log directives:\n%s", body)
	}
	// The log location is host state, not marker data: a tampered marker must
	// not be able to move where logs are written or read.
	if strings.Contains(string(body), `"log_dir"`) || strings.Contains(string(body), `"logs"`) {
		t.Errorf("marker carries log state:\n%s", body)
	}
	if fi, err := os.Stat(m.LogDir); err != nil || !fi.IsDir() {
		t.Errorf("log dir not created by the write path: %v", err)
	}
}

func TestForceHTTPSRedirectBlockAlsoLogs(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.SetSelfSigned("blog", true); err != nil {
		t.Fatalf("SetSelfSigned: %v", err)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	redirect := string(body)[:strings.Index(string(body), "listen 443")]
	if !strings.Contains(redirect, "blog.access.log") {
		t.Errorf("port-80 redirect block has no access log; force-HTTPS traffic would leave no trace:\n%s", redirect)
	}
}

func TestReadLogTailTruncationAndMissing(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// No file yet: a real answer, not an error.
	got, err := m.ReadLog("blog", LogKindAccess, 10)
	if err != nil {
		t.Fatalf("ReadLog on missing file: %v", err)
	}
	if got.Exists || len(got.Lines) != 0 || got.Path != filepath.Join(m.LogDir, "blog.access.log") {
		t.Errorf("missing-file answer = %+v", got)
	}

	path := filepath.Join(m.LogDir, "blog.access.log")
	var lines []string
	for i := 1; i <= 30; i++ {
		lines = append(lines, fmt.Sprintf("line-%02d", i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = m.ReadLog("blog", LogKindAccess, 10)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if !got.Exists || !got.Truncated || len(got.Lines) != 10 {
		t.Fatalf("tail answer = %+v", got)
	}
	if got.Lines[0] != "line-21" || got.Lines[9] != "line-30" {
		t.Errorf("tail = %v, want line-21..line-30", got.Lines)
	}
	if got.Size != int64(len(strings.Join(lines, "\n"))+1) {
		t.Errorf("size = %d", got.Size)
	}
	got, err = m.ReadLog("blog", LogKindAccess, 500)
	if err != nil || got.Truncated || len(got.Lines) != 30 {
		t.Errorf("full read = %+v, err=%v", got, err)
	}
	// Empty file: exists, zero lines, no truncation.
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = m.ReadLog("blog", LogKindAccess, 10)
	if err != nil || !got.Exists || len(got.Lines) != 0 || got.Truncated {
		t.Errorf("empty access log = %+v, err=%v", got, err)
	}
	// The error kind reads its own file, not the access one.
	errPath := filepath.Join(m.LogDir, "blog.error.log")
	if err := os.WriteFile(errPath, []byte("2026/11/12 [error] boom\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = m.ReadLog("blog", LogKindError, 10)
	if err != nil || !got.Exists || len(got.Lines) != 1 || !strings.Contains(got.Lines[0], "boom") {
		t.Errorf("error log read = %+v, err=%v", got, err)
	}
}

func TestReadLogWindowDropsPartialFirstLine(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// A file larger than the read window: every returned line must still be
	// a complete line, never a mid-line fragment.
	line := strings.Repeat("x", 200)
	var sb strings.Builder
	for sb.Len() < logTailWindow+4096 {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	path := filepath.Join(m.LogDir, "blog.access.log")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadLog("blog", LogKindAccess, 100)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if !got.Truncated || len(got.Lines) != 100 {
		t.Fatalf("windowed answer = exists=%v truncated=%v lines=%d", got.Exists, got.Truncated, len(got.Lines))
	}
	for _, l := range got.Lines {
		if l != line {
			t.Fatalf("partial line leaked into the tail: %q", l[:min(40, len(l))])
		}
	}
}

func TestReadLogValidatesKindLinesAndOwnership(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.ReadLog("blog", "secret", 10); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad kind err = %v, want ErrInvalid", err)
	}
	for _, n := range []int{0, -1, maxLogLines + 1} {
		if _, err := m.ReadLog("blog", LogKindAccess, n); !errors.Is(err, ErrInvalid) {
			t.Errorf("lines=%d err = %v, want ErrInvalid", n, err)
		}
	}
	if _, err := m.ReadLog("ghost", LogKindAccess, 10); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown site err = %v, want ErrNotFound", err)
	}
	// A foreign vhost in the same directory is not readable through the viewer.
	foreign := filepath.Join(m.Layout.Dir(), "intruder.conf")
	if err := os.WriteFile(foreign, []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadLog("intruder", LogKindAccess, 10); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign site err = %v, want ErrNotFound", err)
	}
}

// stripLogLines simulates a vhost written before per-site logs existed.
func stripLogLines(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, l := range strings.Split(string(body), "\n") {
		if strings.Contains(l, "access_log ") || strings.Contains(l, "error_log ") {
			continue
		}
		kept = append(kept, l)
	}
	old := []byte(strings.Join(kept, "\n"))
	if err := os.WriteFile(path, old, 0o644); err != nil {
		t.Fatal(err)
	}
	return old
}

func TestMigrateSiteLogsRewritesPanelVhostsOnly(t *testing.T) {
	m, rec := newTestManager(t)
	for _, name := range []string{"blog", "shop"} {
		if _, err := m.Create(Spec{Name: name, Domains: []string{name + ".example.com"}}); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	oldBlog := stripLogLines(t, m.Layout.ConfigPath("blog"))
	oldShop := stripLogLines(t, m.Layout.ConfigPath("shop"))
	if strings.Contains(string(oldBlog), "access_log") || strings.Contains(string(oldShop), "access_log") {
		t.Fatal("test setup did not produce pre-log vhosts")
	}
	foreign := filepath.Join(m.Layout.Dir(), "handmade.conf")
	foreignBody := []byte("# no marker\nserver { listen 80; server_name other.example.com; }\n")
	if err := os.WriteFile(foreign, foreignBody, 0o644); err != nil {
		t.Fatal(err)
	}

	rec.cmds = nil
	if err := m.MigrateSiteLogs(); err != nil {
		t.Fatalf("MigrateSiteLogs: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("migration must be one transaction, got %v", rec.cmds)
	}
	for _, name := range []string{"blog", "shop"} {
		body, _ := os.ReadFile(m.Layout.ConfigPath(name))
		if !strings.Contains(string(body), name+".access.log") {
			t.Errorf("%s not migrated:\n%s", name, body)
		}
	}
	if got, _ := os.ReadFile(foreign); string(got) != string(foreignBody) {
		t.Errorf("foreign file was touched:\n%s", got)
	}
	// Idempotent: a second run changes nothing and reloads nothing.
	rec.cmds = nil
	if err := m.MigrateSiteLogs(); err != nil {
		t.Fatalf("second MigrateSiteLogs: %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("up-to-date vhosts were rewritten: %v", rec.cmds)
	}
}

func TestMigrateSiteLogsRollsBackWhenNginxRefuses(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	old := stripLogLines(t, m.Layout.ConfigPath("blog"))
	rec.failOn = "-t"
	err := m.MigrateSiteLogs()
	if !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("err = %v, want ErrConfigRejected", err)
	}
	got, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(got) != string(old) {
		t.Errorf("failed migration did not restore exact bytes:\n%s", got)
	}
}

func TestNginxUserParsing(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		conf string
		want string
	}{
		{"user www-data;\nevents {}\n", "www-data"},
		{"user nginx nginx;\n", "nginx"},
		{"  user  \"www-data\" ;\n", "www-data"},
		{"# user root;\nevents {}\n", "nobody"},
		{"events {}\n", "nobody"},
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(c.conf), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := nginxUser(dir); got != c.want {
			t.Errorf("nginxUser(%q) = %q, want %q", c.conf, got, c.want)
		}
	}
	if got := nginxUser(filepath.Join(dir, "missing")); got != "nobody" {
		t.Errorf("missing nginx.conf user = %q, want nobody", got)
	}
}
