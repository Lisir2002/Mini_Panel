package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/lockout"
)

// commandRE pulls `minipanel <subcommand>` out of a table row's undo text, and
// flagRE the flags that follow it. Both are checked against the things they have
// to be checked against: dispatch's switch and the usage block.
var (
	commandRE = regexp.MustCompile(`minipanel ([a-z][a-z0-9-]*)`)
	flagRE    = regexp.MustCompile(`--[a-z][a-z0-9-]+`)
)

// probeDispatch runs a subcommand with a flag nobody defined. The command stops in
// flag.Parse without touching anything, and prints its own usage to stderr while
// doing so — which is exactly the output a reviewer does not want to read five
// times, so stderr goes to /dev/null for the call.
func probeDispatch(args []string) error {
	old := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	os.Stderr = devNull
	defer func() {
		os.Stderr = old
		_ = devNull.Close()
	}()
	return dispatch(args)
}

// The 「CLI 对照」page and `minipanel doctor` are one table with two views
// (internal/lockout). Two things can go wrong here and both are silent:
//
//   - the table names a command that does not exist, so the page tells a locked-out
//     operator to run something that fails;
//   - the two views stop matching, so the page and the self-check disagree about
//     the same machine.
//
// Both are checked against the real dispatch switch and the real doctor output.

func TestEveryLockoutRowNamesACommandThatExists(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := dispatch([]string{"passwd", "admin", "--password", "First!2026pass"}); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	e, err := bootstrap()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	defer e.st.Close()
	// Arm a second switch, so the rows exercised are not just the ones a fresh
	// install happens to have.
	if err := e.st.SetSetting("panel.ip_allowlist", "203.0.113.7\n127.0.0.1\n"); err != nil {
		t.Fatalf("allowlist: %v", err)
	}

	rows := lockout.Risks(e.st, e.cfg)
	if len(rows) == 0 {
		t.Fatal("表是空的")
	}
	probe := "--zz-symmetry-probe"
	seen := map[string]bool{}
	for _, r := range rows {
		for _, seg := range commandRE.FindAllStringSubmatch(r.Undo, -1) {
			cmd := seg[1]
			seen[cmd] = true
			// A bogus flag makes every real subcommand fail in flag.Parse, before it
			// can touch anything; an unknown command fails in dispatch instead. The
			// difference is the assertion, and nothing runs either way.
			err := probeDispatch([]string{cmd, probe})
			if err != nil && strings.Contains(err.Error(), "未知命令") {
				t.Errorf("%q 这一行的自救命令 %q 不存在：%+v", r.Name, cmd, err)
			}
			if !strings.Contains(usage, "minipanel "+cmd) {
				t.Errorf("表里引用了 %q，但 usage 没有它", cmd)
			}
		}
		for _, seg := range flagRE.FindAllStringSubmatch(r.Undo, -1) {
			if !strings.Contains(usage, seg[0]) {
				t.Errorf("%q 这一行写了 %s，usage 里没有这个 flag", r.Name, seg[0])
			}
		}
	}
	// Every recovery command the panel has must be reachable from the table, not
	// just the ones this particular machine happens to have armed: a switch that
	// can lock you out and is missing here is the gap §6.3 was written to catch.
	for _, cmd := range []string{"passwd", "reset-entrance", "reset-ips", "reset-2fa", "init"} {
		if !seen[cmd] {
			t.Errorf("表里没有任何一行提到 minipanel %s", cmd)
		}
	}
}

// TestDoctorAndThePageReadTheSameRows is the reason internal/lockout exists. The
// API handler and doctor call the same function; this pins the part that function
// could still get wrong — that doctor's list is exactly the armed subset of what
// the endpoint returns.
func TestDoctorAndThePageReadTheSameRows(t *testing.T) {
	isolated(t)
	if err := dispatch([]string{"init", "--insecure-no-tls"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := dispatch([]string{"passwd", "admin", "--password", "First!2026pass"}); err != nil {
		t.Fatalf("passwd: %v", err)
	}
	e, err := bootstrap()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	defer e.st.Close()

	out, err := captureStdout(t, func() error { return dispatch([]string{"doctor", "--json"}) })
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	var doc struct {
		LockoutRisks []lockout.Risk `json:"lockout_risks"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("doctor --json 不是可读的 JSON：%v\n%s", err, out)
	}

	// Same store, same config, right now: doctor must print exactly the armed rows.
	all := lockout.Risks(e.st, e.cfg)
	want := lockout.OnlyArmed(all)
	if len(doc.LockoutRisks) != len(want) {
		t.Fatalf("doctor 打印了 %d 行，armed 实际 %d 行\n%+v", len(doc.LockoutRisks), len(want), doc.LockoutRisks)
	}
	for i := range want {
		if doc.LockoutRisks[i] != want[i] {
			t.Errorf("doctor 第 %d 行与接口会返回的那行不同：\n  doctor：%+v\n  表：%+v", i, doc.LockoutRisks[i], want[i])
		}
	}
	// And nothing armed slipped out of the filter, which is the same bug seen from
	// the other side: a page that says "3 项当前能关住你" while doctor names 2.
	for _, r := range doc.LockoutRisks {
		if !r.Armed {
			t.Errorf("doctor 列出了未武装的行 %q：%s", r.Name, r.State)
		}
	}
}
