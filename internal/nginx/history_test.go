package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newHistoryManager is the sites-layout harness with the durable snapshot
// layer turned on, pointing at a scratch history directory.
func newHistoryManager(t *testing.T) (*Manager, *recorder, string) {
	t.Helper()
	m, rec := newTestManager(t)
	hist := filepath.Join(t.TempDir(), "config-history")
	m.HistoryDir = hist
	return m, rec, hist
}

// readHistory returns the snapshot entries for one object, oldest first.
func readHistory(t *testing.T, hist, object string) []historyMeta {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(hist, object))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	out := []historyMeta{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(hist, object, e.Name(), "meta.json"))
		if err != nil {
			t.Fatalf("meta.json missing in %s: %v", e.Name(), err)
		}
		var meta historyMeta
		if err := json.Unmarshal(b, &meta); err != nil {
			t.Fatalf("meta.json invalid: %v", err)
		}
		out = append(out, meta)
	}
	return out
}

func TestHistorySnapshotsPreWriteBytes(t *testing.T) {
	m, _, hist := newHistoryManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	obj := FileName("blog")
	// Create snapshots the absence of the file.
	entries := readHistory(t, hist, obj)
	if len(entries) != 1 || entries[0].Existed || entries[0].Size != 0 {
		t.Fatalf("create snapshot = %+v, want one absent-entry", entries)
	}
	before, err := os.ReadFile(m.Layout.ConfigPath("blog"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetAutoIndex("blog", true); err != nil {
		t.Fatalf("SetAutoIndex: %v", err)
	}
	entries = readHistory(t, hist, obj)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	last := entries[len(entries)-1]
	if !last.Existed || last.Size != len(before) || last.Path != m.Layout.ConfigPath("blog") {
		t.Errorf("meta = %+v, want existed size %d path %s", last, len(before), m.Layout.ConfigPath("blog"))
	}
	sum := sha256.Sum256(before)
	if last.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 mismatch")
	}
	// The body must be the exact pre-write bytes.
	ents, _ := os.ReadDir(filepath.Join(hist, obj))
	body, err := os.ReadFile(filepath.Join(hist, obj, ents[len(ents)-1].Name(), "body"))
	if err != nil || string(body) != string(before) {
		t.Errorf("snapshot body differs from pre-write bytes: %v", err)
	}
}

func TestHistoryNoChangeWritesNoSnapshot(t *testing.T) {
	m, _, hist := newHistoryManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	n := len(readHistory(t, hist, FileName("blog")))
	// Same value again: applyFiles reports no change and must not snapshot.
	if _, err := m.SetAutoIndex("blog", false); err != nil {
		t.Fatalf("SetAutoIndex: %v", err)
	}
	if got := len(readHistory(t, hist, FileName("blog"))); got != n {
		t.Errorf("no-op write added a snapshot: %d -> %d", n, got)
	}
}

func TestHistorySnapshotSurvivesFailedTransaction(t *testing.T) {
	m, rec, hist := newHistoryManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	rec.failOn = "-t"
	if _, err := m.SetAutoIndex("blog", true); !errors.Is(err, ErrConfigRejected) {
		t.Fatalf("error = %v, want ErrConfigRejected", err)
	}
	// The live file is restored, and the snapshot of the pre-write bytes is
	// still on disk — the durable half does not depend on the transaction
	// succeeding.
	entries := readHistory(t, hist, FileName("blog"))
	last := entries[len(entries)-1]
	if !last.Existed || last.Size != len(before) {
		t.Fatalf("failed transaction lost its snapshot: %+v", last)
	}
}

func TestHistoryFailureRefusesWrite(t *testing.T) {
	m, rec, hist := newHistoryManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	// Point HistoryDir at a regular file: MkdirAll under it must fail, and
	// the write must be refused with the live file untouched.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.HistoryDir = blocker
	rec.cmds = nil
	if _, err := m.SetAutoIndex("blog", true); err == nil || !strings.Contains(err.Error(), "配置历史") {
		t.Fatalf("error = %v, want history refusal", err)
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	if string(after) != string(before) {
		t.Errorf("live file changed despite refused snapshot")
	}
	if len(rec.cmds) != 0 {
		t.Errorf("nginx commands ran on a refused write: %v", rec.cmds)
	}
	_ = hist
}

func TestHistoryPrunesToDepthLimit(t *testing.T) {
	m, _, hist := newHistoryManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Fixed clock: every snapshot lands in the same timestamp bucket, the
	// suffix loop keeps them distinct, and the prune must still cap them.
	for i := 0; i < historyKeep+10; i++ {
		if _, err := m.SetAutoIndex("blog", i%2 == 0); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	ents, err := os.ReadDir(filepath.Join(hist, FileName("blog")))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != historyKeep {
		t.Errorf("entries = %d, want capped at %d", len(ents), historyKeep)
	}
}

func TestHistoryTLSWritePathSnapshots(t *testing.T) {
	m, _, hist := newHistoryManager(t)
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, _ := os.ReadFile(m.Layout.ConfigPath("blog"))
	// writeConfig is the TLS path's writer, outside applyFiles.
	if err := m.writeConfig(m.Layout.ConfigPath("blog"), string(before)+"# tls edit\n"); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	entries := readHistory(t, hist, FileName("blog"))
	last := entries[len(entries)-1]
	if !last.Existed || last.Size != len(before) {
		t.Fatalf("writeConfig did not snapshot: %+v", last)
	}
}

func TestHistoryEnabledMoveSnapshots(t *testing.T) {
	m, _ := newConfDManager(t)
	hist := filepath.Join(t.TempDir(), "config-history")
	m.HistoryDir = hist
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	n := len(readHistory(t, hist, FileName("blog")))
	if _, err := m.SetEnabled("blog", false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if got := len(readHistory(t, hist, FileName("blog"))); got != n+1 {
		t.Errorf("stop did not snapshot: %d -> %d", n, got)
	}
	if _, err := m.SetEnabled("blog", true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if got := len(readHistory(t, hist, FileName("blog"))); got != n+2 {
		t.Errorf("enable did not snapshot: %d -> %d", n+1, got)
	}
}

func TestHistoryInertWhenUnset(t *testing.T) {
	m, _ := newTestManager(t) // HistoryDir empty
	if _, err := m.Create(Spec{Name: "blog", Domains: []string{"blog.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.snapshotHistory(m.Layout.ConfigPath("blog")); err != nil {
		t.Errorf("inert layer errored: %v", err)
	}
}
