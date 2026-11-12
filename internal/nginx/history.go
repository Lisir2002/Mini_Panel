package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Config-history snapshots are the twenty-fourth slice of M2, and they exist
// because 功能设计.md §5.2 made them a write-protocol requirement from M2 on:
// "任何跨子系统写入前，面板自己必须已经能撤回". The in-memory rollback inside
// applyFiles already guarantees a failed transaction changes nothing; this
// layer adds the durable half — the exact pre-write bytes on disk, so a
// change that nginx *accepted* can still be inspected and (from M4's UI)
// restored later.
//
// Shape: <HistoryDir>/<对象>/<UTC 时间戳>/body + meta.json. The object is the
// config file's base name; the timestamp carries nanoseconds so two writes in
// the same second never collide. meta.json records the absolute path, time,
// SHA-256 and whether the file existed at all (a creation snapshots "absent").
// Actor and params_hash are deliberately not duplicated here: every panel
// write already passes auditWrites, and the audit entry at the same instant
// carries them — one source of truth per fact.
//
// Honesty rule: when HistoryDir is configured, a snapshot that cannot be
// written REFUSES the write. "可回滚是功能，不是提示文案" — a panel that keeps
// writing after its history disk is full would be claiming a safety net it
// no longer has. When HistoryDir is empty (unit harnesses, embedded uses) the
// layer is inert.

// historyKeep caps the snapshots kept per object. §5.2 requires a depth limit
// so the snapshot chain cannot grow without bound; the oldest entries are
// pruned after each successful snapshot.
const historyKeep = 50

// historyMeta is the meta.json beside every snapshot body.
type historyMeta struct {
	Path    string `json:"path"`
	At      string `json:"at"`
	SHA256  string `json:"sha256,omitempty"`
	Size    int    `json:"size"`
	Existed bool   `json:"existed"`
}

// snapshotHistory saves the current bytes of path (or its absence) under
// HistoryDir before a write replaces them. It is a no-op when HistoryDir is
// empty. Any failure is returned so the caller can refuse the write.
func (m *Manager) snapshotHistory(path string) error {
	if m.HistoryDir == "" {
		return nil
	}
	prev, existed := readMaybe(path)
	now := m.now().UTC()
	base := filepath.Join(m.HistoryDir, filepath.Base(path))
	dir := filepath.Join(base, now.Format("20060102T150405.000000000Z"))
	// A fixed clock (tests) or two writes inside one nanosecond tick must not
	// overwrite an earlier snapshot: suffix until the name is free. Any
	// Lstat error other than "exists" (e.g. ENOTDIR because HistoryDir is a
	// file) breaks the loop and is reported by MkdirAll below.
	for i := 1; ; i++ {
		if _, err := os.Lstat(dir); err != nil {
			break
		}
		dir = filepath.Join(base, fmt.Sprintf("%s-%06d", now.Format("20060102T150405.000000000Z"), i))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("写入配置历史目录: %w", err)
	}
	meta := historyMeta{Path: path, At: now.Format(time.RFC3339Nano), Size: len(prev), Existed: existed}
	if existed {
		sum := sha256.Sum256(prev)
		meta.SHA256 = hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(dir, "body"), prev, 0o600); err != nil {
			return fmt.Errorf("写入配置历史快照: %w", err)
		}
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("序列化配置历史元数据: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), mb, 0o600); err != nil {
		return fmt.Errorf("写入配置历史元数据: %w", err)
	}
	m.pruneHistory(filepath.Dir(dir))
	return nil
}

// pruneHistory keeps only the newest historyKeep entries for one object.
// Pruning is best-effort: a prune failure must not undo a snapshot that was
// already written, and the next write retries the prune.
func (m *Manager) pruneHistory(objDir string) {
	ents, err := os.ReadDir(objDir)
	if err != nil || len(ents) <= historyKeep {
		return
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // timestamp names sort chronologically
	for _, n := range names[:len(names)-historyKeep] {
		_ = os.RemoveAll(filepath.Join(objDir, n))
	}
}
