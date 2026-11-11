package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/lockout"
)

// The 「CLI 对照」endpoint exists for one reason: the page and `minipanel doctor`
// must not be able to tell different stories about the same switch. These cases
// are written so that story cannot drift — the response is compared against the
// same function doctor calls, in the same process, and a switch flipped through the
// normal settings API has to show up in it.

func auditRows(t *testing.T, p *panel) int {
	t.Helper()
	var n int
	if err := p.st.DB().QueryRow(`SELECT COUNT(1) FROM audit`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func TestLockoutRisksNeedASession(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	// Not logged in: the disguised answer, the same one every other API path gives,
	// so this page does not become a marker for "there is a panel here".
	r, _ := p.get("/api/v1/lockout-risks")
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("未登录 GET /lockout-risks = %d，期望伪装响应 404", r.StatusCode)
	}
}

func TestLockoutRisksAnswerIsTheFunctionDoctorUses(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	if r, b := p.login(); r.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", r.StatusCode, b)
	}

	r, body := p.get("/api/v1/lockout-risks")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET /lockout-risks = %d %s", r.StatusCode, body)
	}
	var got struct {
		Items      []lockout.Risk `json:"items"`
		Armed      int            `json:"armed"`
		Total      int            `json:"total"`
		Executable *bool          `json:"executable"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}

	// Compared in-process against the very call `doctor` makes. If someone gives the
	// handler its own computation, this is where it shows up.
	want := lockout.Risks(p.st, p.cfg)
	if len(got.Items) != len(want) || got.Total != len(want) {
		t.Fatalf("行数 = %d/%d，期望 %d", len(got.Items), got.Total, len(want))
	}
	for i := range want {
		if got.Items[i] != want[i] {
			t.Errorf("第 %d 行与 lockout.Risks 不一致：\n  接口：%+v\n  计算：%+v", i, got.Items[i], want[i])
		}
	}
	armed := 0
	for _, it := range want {
		if it.Armed {
			armed++
		}
	}
	if got.Armed != armed {
		t.Errorf("armed = %d，实际 %d 行为真", got.Armed, armed)
	}
	// The page's read-only promise is a field, not a comment: if a write path is
	// ever added beside this table, `executable` has to change and this fails.
	if got.Executable == nil || *got.Executable {
		t.Errorf("executable 必须是 false，得到 %v", got.Executable)
	}
}

func TestLockoutRisksFollowsASwitchFlippedThroughTheAPI(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	if r, b := p.login(); r.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", r.StatusCode, b)
	}

	find := func() lockout.Risk {
		t.Helper()
		r, body := p.get("/api/v1/lockout-risks")
		if r.StatusCode != http.StatusOK {
			t.Fatalf("GET /lockout-risks = %d %s", r.StatusCode, body)
		}
		var got struct {
			Items []lockout.Risk `json:"items"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, it := range got.Items {
			if it.Name == "IP 白名单" {
				return it
			}
		}
		t.Fatal("接口没有返回 IP 白名单这一行")
		return lockout.Risk{}
	}

	before := find()
	if before.Armed {
		t.Fatalf("新面板不该一上来就武装白名单：%s", before.State)
	}
	// 127.0.0.1 has to stay in the list, and that is the point of the row: the one
	// request that would undo a bad allowlist is itself an http request. A test that
	// wrote only 203.0.113.7 would lock *itself* out with a 403 ip_not_allowed,
	// which is the defect §6.3 G-A was filed against — `reset-ips` is the way back.
	if r, b := p.do(http.MethodPut, "/api/v1/settings/panel.ip_allowlist",
		`{"value":"203.0.113.7\n127.0.0.1"}`, p.csrfHeader()); r.StatusCode != http.StatusOK {
		t.Fatalf("写白名单 = %d %s", r.StatusCode, b)
	}
	after := find()
	if !after.Armed || !strings.Contains(after.State, "2 条") {
		t.Errorf("写完白名单这一行仍然说没武装：%+v", after)
	}
	// The undo text must name the command that actually clears it, because this row
	// is the one that locks out the request that would fix it.
	if !strings.Contains(after.Undo, "reset-ips") {
		t.Errorf("白名单行的自救命令不对：%s", after.Undo)
	}
}

func TestLockoutRisksReadsWriteNoAudit(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	if r, b := p.login(); r.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", r.StatusCode, b)
	}
	// The login itself is audited; what matters is that reading this table is not.
	// A page that is polled would otherwise fill the log the design doc promises is
	// append-only evidence of *actions*.
	before := auditRows(t, p)
	for i := 0; i < 3; i++ {
		if r, _ := p.get("/api/v1/lockout-risks"); r.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次 GET = %d", i+1, r.StatusCode)
		}
	}
	if after := auditRows(t, p); after != before {
		t.Errorf("只读页写了审计：%d → %d", before, after)
	}
}

func TestLockoutRisksIsGatedLikeEverythingElse(t *testing.T) {
	p := newPanel(t, nil)
	p.createAdmin()
	p.visitEntrance()
	if r, b := p.login(); r.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", r.StatusCode, b)
	}
	u, err := p.st.UserByUsername(adminName)
	if err != nil {
		t.Fatalf("read admin: %v", err)
	}
	if err := p.st.SetMustChange(u.ID, true); err != nil {
		t.Fatalf("set must change: %v", err)
	}
	r, body := p.get("/api/v1/lockout-risks")
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("闸门期间 GET = %d %s，期望 403", r.StatusCode, body)
	}
	if !strings.Contains(body, "password_change_required") {
		t.Errorf("闸门没有说清楚要先改口令：%s", body)
	}
	// Deliberate, and stated in openapi/panel.yaml: the gate's remedy is in the
	// panel already, so this table is not one of its three allowed paths.
}
