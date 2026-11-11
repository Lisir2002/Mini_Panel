package lockout

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/config"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "minipanel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testCfg(dir string) *config.Config {
	return &config.Config{
		Bind: "127.0.0.1", Port: 29080, Entrance: "/zq4k7m2p", TLS: false,
		DataDir: dir, LogDir: dir, SessionTTL: config.Duration(2 * time.Hour),
		LoginLimit: 5, UnauthStatus: 404,
	}
}

func row(t *testing.T, rs []Risk, name string) Risk {
	t.Helper()
	for _, r := range rs {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("表里没有 %q 这一行", name)
	return Risk{}
}

// TestTableIsTheWholeDocumentedSwitchList is the §6.3 ↔ §3.10 correspondence check.
// The page and `doctor` exist to answer "can this shut me out, and what undoes
// it", so a row that disappears here is a switch nobody can find the rescue for.
// The names are the ones docs/功能设计.md §6.3 uses, plus the two the table splits
// out (证书 from 监听/TLS, 待确认口令 from 口令).
func TestTableIsTheWholeDocumentedSwitchList(t *testing.T) {
	dir := t.TempDir()
	rs := Risks(openStore(t), testCfg(dir))
	want := []string{
		"安全入口", "管理员口令", "监听地址 / 端口", "面板证书", "会话时长 / 登录失败锁定",
		"两步验证", "IP 白名单", "口令有效期", "口令待确认",
	}
	if len(rs) != len(want) {
		t.Fatalf("表有 %d 行，期望 %d 行：%s", len(rs), len(want), strings.Join(names(rs), " / "))
	}
	for _, n := range want {
		r := row(t, rs, n)
		// Every row has to say something and offer something: an armed row
		// without a command is the bug §6.3 was written to catch, and a row with
		// an empty state is a page that renders a blank cell and a shrug.
		if strings.TrimSpace(r.State) == "" {
			t.Errorf("%s: 状态为空", n)
		}
		if strings.TrimSpace(r.Undo) == "" {
			t.Errorf("%s: 没有解锁路径", n)
		}
	}
	// Order is part of the contract: the UI renders it without re-sorting.
	for i := range rs {
		if rs[i].Name != want[i] {
			t.Errorf("第 %d 行是 %q，期望 %q", i, rs[i].Name, want[i])
		}
	}
}

func names(rs []Risk) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

// TestArmedTracksTheSwitchBeingOn pins what `doctor` prints. doctor's list is the
// armed rows only, so an entry appearing there when nothing is armed — or vanishing
// when something is — is the panel lying about the machine's state.
func TestArmedTracksTheSwitchBeingOn(t *testing.T) {
	st := openStore(t)
	cfg := testCfg(t.TempDir())

	// An empty database arms exactly one row: the entrance, which lives in
	// panel.json rather than in the store. 管理员口令 with zero users is not armed,
	// because there is nothing yet to have forgotten.
	if got := names(OnlyArmed(Risks(st, cfg))); len(got) != 1 || got[0] != "安全入口" {
		t.Fatalf("空库应当只有入口一行武装，实际：%s", strings.Join(got, " / "))
	}
	if err := st.SetSetting("panel.ip_allowlist", "203.0.113.7\n203.0.113.8\n"); err != nil {
		t.Fatalf("set allowlist: %v", err)
	}
	rs := Risks(st, cfg)
	ip := row(t, rs, "IP 白名单")
	if !ip.Armed {
		t.Errorf("写了白名单却没有武装：%s", ip.State)
	}
	if !strings.Contains(ip.State, "2 条") {
		t.Errorf("条数没有如实写：%s", ip.State)
	}
	if len(OnlyArmed(rs)) != 2 { // 入口 + IP 白名单
		t.Errorf("armed 行数 = %d，期望 2：%s", len(OnlyArmed(rs)), strings.Join(names(OnlyArmed(rs)), " / "))
	}

	// Clearing it must un-arm the row: this is the exact transition the operator
	// performs with `reset-ips --clear` while standing outside the panel.
	if err := st.SetSetting("panel.ip_allowlist", "\n"); err != nil {
		t.Fatalf("clear allowlist: %v", err)
	}
	if row(t, Risks(st, cfg), "IP 白名单").Armed {
		t.Error("清空的白名单仍然武装")
	}
}

// TestExpiryRowReadsTheValueTheSameWayTheMiddlewareDoes. The enforcement point is
// internal/api/auth.go passwordExpired: 0, negative and unparsable all mean "no
// expiry". If this table armed on "0" the page would warn about a policy the panel
// does not apply, which is the false sense of safety G-B was filed against.
func TestExpiryRowReadsTheValueTheSameWayTheMiddlewareDoes(t *testing.T) {
	st := openStore(t)
	cfg := testCfg(t.TempDir())
	for _, v := range []string{"", "0", "-1", "abc", "  "} {
		if err := st.SetSetting("panel.password_expiry_days", v); err != nil {
			t.Fatalf("set %q: %v", v, err)
		}
		if r := row(t, Risks(st, cfg), "口令有效期"); r.Armed {
			t.Errorf("值 %q 被当成有效期，但 passwordExpired 不会：%s", v, r.State)
		}
	}
	if err := st.SetSetting("panel.password_expiry_days", "30"); err != nil {
		t.Fatal(err)
	}
	r := row(t, Risks(st, cfg), "口令有效期")
	if !r.Armed || !strings.Contains(r.State, "30 天") {
		t.Errorf("30 天没有如实武装：%s", r.State)
	}
}

// TestUnreadableStoreIsSaidNotHidden: a row cannot answer "off" just because the
// database would not say. This is the state `doctor` is most likely to be run in.
func TestUnreadableStoreIsSaidNotHidden(t *testing.T) {
	rs := Risks(nil, testCfg(t.TempDir()))
	quiet := 0
	for _, r := range rs {
		if strings.Contains(r.State, "读不出来") || strings.Contains(r.State, "读取失败") {
			quiet++
			if r.Armed {
				t.Errorf("%s 在读不到的情况下声称武装", r.Name)
			}
		}
	}
	// 口令 / 2FA / 待确认 read the users table, 白名单 / 有效期 read settings:
	// five rows must be the honest "I could not read" ones, not silent "no".
	if quiet != 5 {
		t.Errorf("只有 %d 行如实报告了读不到，期望 5：%s", quiet, strings.Join(names(rs), " / "))
	}
}

// TestEntranceValueIsNotInTheTable: the path is a secret the panel does not echo
// into responses, audit rows or logs (README 安全入口一节). This table is served
// over HTTP, so it must describe the switch without naming it.
func TestEntranceValueIsNotInTheTable(t *testing.T) {
	cfg := testCfg(t.TempDir())
	cfg.Entrance = "/zq4k7m2p"
	for _, r := range Risks(openStore(t), cfg) {
		if strings.Contains(r.State+r.Undo+r.Name, cfg.Entrance) {
			t.Errorf("%s 行里出现了入口路径本身：%s / %s", r.Name, r.State, r.Undo)
		}
	}
	if !row(t, Risks(openStore(t), cfg), "安全入口").Armed {
		t.Error("设置了入口却没有武装")
	}
	cfg.Entrance = ""
	if r := row(t, Risks(openStore(t), cfg), "安全入口"); r.Armed {
		t.Errorf("入口关闭时不该武装：%s", r.State)
	}
}

// TestCertRowArmsOnlyWhenTLSIsActuallyBroken. TLS on with a certificate that
// cannot serve a handshake is the one config mistake that keeps the panel reachable
// but unusable, so this row must arm on it — and must not arm when TLS is off,
// where the panel still answers on loopback.
func TestCertRowArmsOnlyWhenTLSIsActuallyBroken(t *testing.T) {
	st := openStore(t)
	dir := t.TempDir()
	cfg := testCfg(dir)
	if row(t, Risks(st, cfg), "面板证书").Armed {
		t.Error("TLS 关闭时证书行不该武装")
	}
	cfg.TLS = true
	if !row(t, Risks(st, cfg), "面板证书").Armed {
		t.Error("TLS 开启且证书文件还不存在时应当武装")
	}
	// A real self-signed cert, freshly issued, is usable: the browser warning is a
	// trust question, not a lock-out this panel causes.
	if _, _, err := sec.EnsureSelfSignedTLS(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	r := row(t, Risks(st, cfg), "面板证书")
	if r.Armed {
		t.Errorf("刚签发的证书不该武装：%s", r.State)
	}
	if !strings.Contains(r.State, "到期") {
		t.Errorf("可用时状态应说到期时间：%s", r.State)
	}
}
