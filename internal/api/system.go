package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/build"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
)

var startedAt = time.Now()

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"product":          "Mini Panel",
		"version":          build.Version,
		"commit":           build.Commit,
		"uptime_seconds":   int64(time.Since(startedAt).Seconds()),
		"telemetry":        false,
		"requires_setup":   func() bool { has, _ := s.Store.HasAnyUser(); return !has }(),
		"entrance_enabled": s.Cfg.Entrance != "",
	})
}

// handleCapabilities is the contract the UI renders from. A feature absent here
// must be rendered disabled with the accompanying reason — never as a control
// that is visible, looks clickable, and silently does nothing.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Caps)
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"hostname":   s.Caps.Hostname,
		"os":         s.Caps.OS,
		"os_family":  s.Caps.OSFamily,
		"os_version": s.Caps.OSVersion,
		"arch":       s.Caps.Arch,
		"privileged": s.Caps.IsPrivileged,
		"panel": map[string]any{
			"version":  build.Version,
			"port":     s.Cfg.Port,
			"tls":      s.Cfg.TLS,
			"dataDir":  s.Cfg.DataDir,
			"siteRoot": s.siteRoot(),
		},
	}
	if hi, err := host.Info(); err == nil {
		out["uptime_seconds"] = hi.Uptime
		out["boot_time"] = hi.BootTime
		out["kernel"] = hi.KernelVersion
		out["os_pretty"] = hi.Platform + " " + hi.PlatformVersion
	}
	if n, err := cpu.Counts(true); err == nil {
		out["cpu_cores"] = n
	}
	if m, err := mem.VirtualMemory(); err == nil {
		out["memory"] = map[string]any{"total": m.Total, "used": m.Used, "usedPercent": m.UsedPercent}
	}
	if la, err := load.Avg(); err == nil && la != nil {
		out["load"] = map[string]any{"m1": la.Load1, "m5": la.Load5, "m15": la.Load15}
	}
	writeJSON(w, http.StatusOK, out)
}

// editableSettings is an explicit allow-list. Anything not here cannot be written
// through the API, which keeps "port" and "entrance" (bootstrap values living in
// panel.json) out of reach of a stolen session and forces a deliberate restart.
var editableSettings = map[string]func(string) error{
	"panel.ip_allowlist":         validateIPAllowlist,
	"panel.password_expiry_days": validateNonNegativeInt,
	"panel.basic_auth":           validateBoolString,
	"panel.trust_proxy":          validateBoolString,
}

func (s *Server) handleSettingsList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.DB().Query(`SELECT key,value,updated_at FROM settings ORDER BY key`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取设置失败")
		return
	}
	defer rows.Close()
	type item struct {
		Key      string `json:"key"`
		Value    string `json:"value"`
		Update   int64  `json:"updated_at"`
		Editable bool   `json:"editable"`
		// Source tells the operator where the value actually comes from, which is
		// the difference between a settings page and a guess.
		Source string `json:"source"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.Key, &it.Value, &it.Update); err != nil {
			continue
		}
		_, it.Editable = editableSettings[it.Key]
		it.Source = "db"
		if v, ok := s.runtimeSetting(it.Key); ok {
			// The seeded row is only there so this list has something to show
			// before panel.json existed; the value the process is running with
			// always wins. Reporting the DB mirror instead would advertise a port
			// that is not listening.
			it.Value = v
			it.Source = "panel.json"
		}
		out = append(out, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// runtimeSetting returns the live value of a bootstrap setting, read straight
// from the loaded config. These keys are not writable through the API by
// design: they decide how the panel authenticates, so changing them must go
// through the file on disk (0600) plus a restart, never through a session
// cookie that can be stolen. ok is false for keys the panel does not boot from.
func (s *Server) runtimeSetting(key string) (string, bool) {
	if s == nil || s.Cfg == nil {
		return "", false
	}
	switch key {
	case "panel.entrance":
		if s.Cfg.Entrance == "" {
			return "已关闭（所有路径直接出登录页）", true
		}
		// Deliberately not echoed: the entrance is the camouflage, and a settings
		// row is a screenshot magnet. minipanel doctor prints it on purpose.
		return "已启用（值不在此展示，见 panel.json 或 minipanel doctor）", true
	case "panel.port":
		return strconv.Itoa(s.Cfg.Port), true
	case "panel.ssl":
		return strconv.FormatBool(s.Cfg.TLS), true
	case "panel.session_timeout":
		return strconv.Itoa(int(s.Cfg.SessionTTL.D() / time.Second)), true
	case "panel.login_limit":
		return strconv.Itoa(s.Cfg.LoginLimit), true
	case "panel.unauth_status":
		return strconv.Itoa(s.Cfg.UnauthStatus), true
	}
	return "", false
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	key := chiParam(r, "key")
	validate, ok := editableSettings[key]
	if !ok {
		writeErr(w, http.StatusBadRequest, "immutable", "该设置不能通过 API 修改")
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	if err := validate(body.Value); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_value", err.Error())
		return
	}
	if err := s.Store.SetSetting(key, body.Value); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "写入失败")
		return
	}
	if key == "panel.trust_proxy" {
		SetTrustProxy(body.Value == "true")
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "value": body.Value})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	rows, total, err := s.Audit.List(limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取审计日志失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": rows})
}

// ---- 2FA and password -----------------------------------------------------

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	secret := sec.Base32Secret(10)
	if err := s.Store.SetTOTP(u.ID, secret, false); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "保存密钥失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"url":    sec.TOTPURL(secret, u.Username),
		"note":   "扫码后回到此处输入 6 位口令完成启用；未启用前密钥不生效。",
	})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	row := s.Store.DB().QueryRow(`SELECT totp_secret FROM users WHERE id=?`, u.ID)
	var secret string
	if err := row.Scan(&secret); err != nil || secret == "" {
		writeErr(w, http.StatusBadRequest, "no_secret", "请先调用 /2fa/setup 获取密钥")
		return
	}
	if !sec.VerifyTOTP(secret, body.Code, time.Now()) {
		writeErr(w, http.StatusBadRequest, "bad_code", "动态口令校验失败")
		return
	}
	if err := s.Store.SetTOTP(u.ID, secret, true); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "启用失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"totp_enabled": true})
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	u := CurrentUser(r)
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON")
		return
	}
	dbUser, err := s.Store.UserByUsername(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "读取账号失败")
		return
	}
	if !sec.VerifyPassword(dbUser.PwHash, body.OldPassword) {
		writeErr(w, http.StatusBadRequest, "bad_password", "当前密码不正确")
		return
	}
	if err := sec.ValidatePassword(body.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	hash, err := sec.HashPassword(body.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "kdf", "口令哈希失败")
		return
	}
	if err := s.Store.SetPassword(dbUser.ID, hash, false); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", "更新失败")
		return
	}
	// Rotate every other session: changing a password must not leave an old
	// session valid.
	_, _ = s.Store.DB().Exec(`UPDATE sessions SET revoked=1 WHERE user_id=? AND id<>?`, dbUser.ID, u.SID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- validators -----------------------------------------------------------

func validateIPAllowlist(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if !isCIDR(line) {
				return errors.New("非法 CIDR：" + line)
			}
			continue
		}
		if !isIP(line) {
			return errors.New("非法 IP（仅支持 IP 与 CIDR，不支持域名）：" + line)
		}
	}
	return nil
}

func validateNonNegativeInt(v string) error {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 || n > 3650 {
		return errors.New("取值需为 0-3650")
	}
	return nil
}

func validateBoolString(v string) error {
	switch strings.TrimSpace(v) {
	case "true", "false":
		return nil
	default:
		return errors.New("取值需为 true 或 false")
	}
}

// auditEntry builds a record for the handlers that write outside the middleware
// (the login path, which has no principal until it succeeds).
func auditEntry(r *http.Request, user, action, target string, params map[string]string, result string) audit.Entry {
	return audit.Entry{
		User:   user,
		IP:     clientIP(r),
		Action: action,
		Target: target,
		Params: params,
		Result: result,
	}
}
