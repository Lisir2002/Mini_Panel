// Package lockout is the panel's self-rescue symmetry table: every switch on the
// panel side that can shut the operator out of their own machine, the value it
// currently has, and the minipanel command that undoes it.
//
// It is a package rather than a helper inside cmd/minipanel because two consumers
// read it and they must not be able to disagree:
//
//   - `minipanel doctor` prints OnlyArmed(Risks(...)) — a risk list, the shape it
//     has always had.
//   - GET /api/v1/lockout-risks returns the whole table, because the point of the
//     「CLI 对照」page (docs/功能设计.md §3.10) is that the operator sees the
//     switches *before* one of them bites, not after.
//
// The rule the table encodes is §6.3's: a switch here without a matching
// minipanel command means the only way back in is editing SQLite by hand, which
// is not something this panel should ever ask of somebody who already lost their
// entrance, phone or IP address. cmd/minipanel/main_test.go checks that sentence
// against the real dispatch table.
//
// Reading is best-effort by design: doctor has to answer even when the database
// is half-broken. But a failed read is *said* in the state text instead of being
// shown as "off", because a table that quietly claims a switch is closed is worse
// than no table.
package lockout

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Lisir2002/Mini_Panel/internal/config"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

// Risk is one row of the table.
type Risk struct {
	Name  string `json:"name"`
	State string `json:"state"`
	// Armed says this switch is currently in a state that *can* lock somebody
	// out. Rows that are structural (there is no way to turn them off) or that
	// cannot be observed from a second process report false and say why in State.
	Armed bool   `json:"armed"`
	Undo  string `json:"undo"`
}

// Risks reads the same values the middleware enforces, in the order §6.3 lists
// them. Every row is present in every answer; nothing here is conditional on the
// switch being on.
func Risks(st *store.Store, cfg *config.Config) []Risk {
	if cfg == nil {
		cfg = config.Default()
	}
	var db *sql.DB
	if st != nil {
		db = st.DB()
	}
	return []Risk{
		entranceRow(cfg),
		passwordRow(db),
		listenRow(cfg),
		certRow(cfg),
		sessionRow(cfg),
		totpRow(db),
		allowlistRow(st),
		expiryRow(st),
		mustChangeRow(db),
	}
}

// OnlyArmed is the doctor view: rows that are currently able to lock somebody out.
func OnlyArmed(rs []Risk) []Risk {
	out := make([]Risk, 0, len(rs))
	for _, r := range rs {
		if r.Armed {
			out = append(out, r)
		}
	}
	return out
}

// ---- rows --------------------------------------------------------------

func entranceRow(cfg *config.Config) Risk {
	r := Risk{
		Name: "安全入口",
		// The three forms are exactly what cmdResetEntrance accepts: no flag
		// regenerates a random path, --set picks one, --disable turns the entrance
		// off. Naming a flag that does not exist here would send an operator to a
		// command that fails, which is the opposite of what this table is for —
		// main_test.go checks every --flag in every row against the usage text.
		Undo: "minipanel reset-entrance（重新随机生成）/ --set <路径> / --disable",
	}
	if cfg.Entrance == "" {
		r.State = "未启用：登录页对任何路径可见，所以这一项关不住人"
		return r
	}
	// The path itself is deliberately absent: it is a secret the panel does not
	// echo into any response, log line or audit entry, and this table is read by
	// the API as well as by a terminal.
	r.Armed = true
	switch cfg.UnauthStatus {
	case 444:
		r.State = "已启用：不知道入口路径的请求直接被丢弃（unauth_status=444），连响应体都没有"
	default:
		r.State = fmt.Sprintf("已启用：不知道入口路径的请求按伪装响应回（unauth_status=%d），看上去就是 404", cfg.UnauthStatus)
	}
	return r
}

func passwordRow(db *sql.DB) Risk {
	r := Risk{
		Name: "管理员口令",
		Undo: "minipanel passwd <账号>（关闭 tty 回显，并作废该账号全部会话）",
	}
	n, err := count(db, `SELECT COUNT(1) FROM users`)
	if err != nil {
		r.State = "账号表读不出来：" + err.Error()
		return r
	}
	if n == 0 {
		r.State = "还没有管理员账号，面板启动后会要求初始化"
		return r
	}
	// There is no "passwordless" mode to fall back to and no strength switch to
	// turn off (docs/功能设计.md §3.10), so this row is always armed: the password
	// is the one credential that cannot be removed, only replaced from the CLI.
	r.Armed = true
	r.State = fmt.Sprintf("%d 个账号；口令强度不可关闭，忘了口令在面板侧没有自救入口", n)
	return r
}

func listenRow(cfg *config.Config) Risk {
	return Risk{
		Name:  "监听地址 / 端口",
		Armed: false,
		State: fmt.Sprintf("%s（TLS: %v）。端口被占用时面板直接退出、不换端口——那是「起不来」，"+
			"不是「关在外面」，而且只在启动那一刻发生，从第二个进程里看不到",
			cfg.Addr(), cfg.TLS),
		Undo: "minipanel init --bind <地址> --port <端口> --insecure-no-tls（写引导值前不监听任何东西）",
	}
}

func certRow(cfg *config.Config) Risk {
	r := Risk{
		Name: "面板证书",
		Undo: "minipanel init --insecure-no-tls 先恢复到回环可用，再修证书",
	}
	if !cfg.TLS {
		r.State = "未启用 TLS：登录会被拒绝（口令不能走明文），但面板本身还看得见"
		return r
	}
	path := sec.CertPath(cfg.DataDir)
	info := sec.ReadCert(path)
	switch {
	case info.Err != nil:
		r.Armed = true
		r.State = "证书文件读不出来：" + info.Err.Error()
	case !info.Usable:
		r.Armed = true
		r.State = "TLS 已开启但证书现在不能用于握手：" + info.Summary
	default:
		r.State = info.Summary + "（临期与主机/IP 变化由 init 和启动时的 sec.EnsureSelfSignedTLS 自动重签）"
	}
	return r
}

func sessionRow(cfg *config.Config) Risk {
	ttl := cfg.SessionTTL.D()
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	r := Risk{
		Name:  "会话时长 / 登录失败锁定",
		Armed: false,
		State: fmt.Sprintf("会话 %s；同一 IP 连续 %d 次失败进入锁定并翻倍退避（上限 1 小时）。"+
			"session_ttl 短于 1 分钟会被 config 归一回 12h，所以这项配不出自锁的值；"+
			"失败计数只在内存里，重启面板即清（有意取舍，过程记在审计）",
			ttl, cfg.LoginLimit),
		Undo: "重启面板即清空锁定计数；顺带忘了口令用 minipanel passwd <账号>",
	}
	return r
}

func totpRow(db *sql.DB) Risk {
	r := Risk{
		Name: "两步验证",
		Undo: "minipanel reset-2fa --clear [--user <账号>]（同时作废该账号全部会话）",
	}
	n, err := count(db, `SELECT COUNT(1) FROM users WHERE totp_enabled=1`)
	if err != nil {
		r.State = "读取失败：" + err.Error()
		return r
	}
	if n == 0 {
		r.State = "没有账号开启；密钥只存在本机数据库里，手机丢了不等于账号丢了"
		return r
	}
	r.Armed = true
	r.State = fmt.Sprintf("%d 个账号已开启；密钥只存在本机数据库里，一次性恢复码仍未做", n)
	return r
}

func allowlistRow(st *store.Store) Risk {
	r := Risk{
		Name: "IP 白名单",
		Undo: "minipanel reset-ips --set <cidr 列表> / --clear",
	}
	var raw string
	err := setting(st, "panel.ip_allowlist", &raw)
	if err != nil {
		r.State = "设置项读不出来：" + err.Error()
		return r
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		r.State = "未设置：任何地址都能走到登录页（仍然受入口和口令保护）"
		return r
	}
	n := strings.Count(strings.TrimRight(raw, "\n"), "\n") + 1
	r.Armed = true
	r.State = fmt.Sprintf("已启用，%d 条；不在名单内的地址连登录页都看不到，包括打算修它的那个请求", n)
	return r
}

func expiryRow(st *store.Store) Risk {
	r := Risk{
		Name: "口令有效期",
		Undo: "面板内改口令；忘了旧口令用 minipanel passwd <账号>",
	}
	var raw string
	err := setting(st, "panel.password_expiry_days", &raw)
	if err != nil {
		r.State = "设置项读不出来：" + err.Error()
		return r
	}
	// The same reading as the enforcement point (internal/api/auth.go
	// passwordExpired): 0, negative and unparsable all mean "no expiry", and a
	// password with no recorded change time is never treated as expired.
	trimmed := strings.TrimSpace(raw)
	days, convErr := strconv.Atoi(trimmed)
	if convErr != nil || days <= 0 {
		if trimmed == "" || trimmed == "0" {
			// "0" is what a fresh install stores, so it reads as plainly unset
			// rather than as a value the operator has to decode.
			r.State = "未设置：口令不会到期"
			return r
		}
		r.State = fmt.Sprintf("值是 %q，面板按未设置处理（0、负数、非数字都等于不设）", trimmed)
		return r
	}
	r.Armed = true
	r.State = fmt.Sprintf("每 %d 天要求更换（登录时判定，不打断进行中的会话；到期后只放行改密与登出）", days)
	return r
}

func mustChangeRow(db *sql.DB) Risk {
	r := Risk{
		Name: "口令待确认",
		Undo: "面板内改口令；忘了旧口令用 minipanel passwd <账号>",
	}
	n, err := count(db, `SELECT COUNT(1) FROM users WHERE must_change_pw=1`)
	if err != nil {
		r.State = "读取失败：" + err.Error()
		return r
	}
	if n == 0 {
		r.State = "没有账号欠一次改密"
		return r
	}
	r.Armed = true
	r.State = fmt.Sprintf("%d 个账号除改口令与登出外的请求会被拒绝", n)
	return r
}

// ---- reads -------------------------------------------------------------

func count(db *sql.DB, q string) (int, error) {
	if db == nil {
		return 0, fmt.Errorf("没有可用的数据库")
	}
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func setting(st *store.Store, key string, out *string) error {
	if st == nil {
		return fmt.Errorf("没有可用的数据库")
	}
	v, err := st.GetSetting(key)
	if err != nil {
		return err
	}
	*out = v
	return nil
}
