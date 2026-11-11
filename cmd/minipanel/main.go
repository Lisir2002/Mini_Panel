// Command minipanel is the whole panel: one static binary that serves the API,
// the embedded UI, and the local scheduler. There is no separate web server, no
// PHP, and no python venv to install — which is the point of rewriting it.
//
// Usage:
//
//	minipanel serve              run the panel (foreground; systemd/scm wraps it)
//	minipanel init               create/refresh panel.json, entrance and TLS cert
//	minipanel doctor             print detected paths, capabilities, DB state
//	minipanel passwd <user>      set or reset an administrator password
//	minipanel reset-entrance     generate a new security entrance path
//	minipanel version            print version/commit
//
// Recovery note: every command here works without the panel being reachable over
// HTTP, because an operator who has lost the entrance or the password still has
// SSH. That path is what BaoTa's `bt` menu is for, and it must keep working even
// when the web layer is broken.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Lisir2002/Mini_Panel/internal/api"
	"github.com/Lisir2002/Mini_Panel/internal/audit"
	"github.com/Lisir2002/Mini_Panel/internal/build"
	"github.com/Lisir2002/Mini_Panel/internal/config"
	"github.com/Lisir2002/Mini_Panel/internal/lockout"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
	"github.com/Lisir2002/Mini_Panel/internal/sec"
	"github.com/Lisir2002/Mini_Panel/internal/store"
)

var usage = `Mini Panel ` + build.Version + ` — 云服务器管理面板

  minipanel serve            启动面板（前台运行，由 systemd / 服务管理器托管）
                               --bind <地址>  --port <端口>  --insecure-no-tls
  minipanel init             初始化：写入 panel.json、生成安全入口与面板证书
                               --bind <地址>  --port <端口>  --insecure-no-tls
                               --entrance </路径>（随机生成留空即可；--entrance - 关闭入口）
  minipanel doctor           输出探测到的路径、能力位图与数据库状态（--json）
  minipanel passwd <user>    设置/重置管理员口令（账号不存在时创建，并作废全部会话）
                               --password '<口令>'（省略则从标准输入读取）
  minipanel reset-entrance   重新生成安全入口（--set </路径> | --disable）
  minipanel reset-ips        重写 IP 白名单，用于把自己从门外救回来（--set <列表> | --clear）
  minipanel reset-2fa        关闭两步验证（--clear，必填；同时作废该账号全部会话）
                               --user <账号>（只有一个管理员时可省略）
  minipanel version          版本信息

任何子命令加 -h 打印它自己的选项。
口令写法：minipanel passwd admin --password 'X'，或 echo 'X' | minipanel passwd admin。
被自己关在门外时：minipanel reset-entrance 找回入口，reset-ips 清掉白名单，
reset-2fa --clear 关掉两步验证；三条都在本机执行，都不需要面板可用。
`

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// `-h` on a subcommand is a question, not a failure.
			fmt.Print(usage)
			return
		}
		fmt.Fprintln(os.Stderr, "minipanel:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest)
	case "init":
		return cmdInit(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "passwd":
		return cmdPasswd(rest)
	case "reset-entrance":
		return cmdResetEntrance(rest)
	case "reset-ips":
		return cmdResetIPs(rest)
	case "reset-2fa":
		return cmdReset2FA(rest)
	case "version":
		fmt.Printf("Mini Panel %s (commit %s, built %s)\n", build.Version, build.Commit, build.BuildDate)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("未知命令 %q\n%s", cmd, usage)
	}
}

// ---- shared bootstrap ------------------------------------------------------

type env struct {
	plat   platform.Platform
	dir    string // config dir holding panel.json
	cfg    *config.Config
	st     *store.Store
	caps   *platform.Capabilities
	log    *slog.Logger
	exists bool // panel.json already on disk
}

func bootstrap() (*env, error) {
	plat := platform.Current()
	dir := plat.ConfigDir()
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("读取配置: %w", err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = plat.DataDir()
	}
	if cfg.LogDir == "" {
		cfg.LogDir = plat.LogDir()
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置不合法: %w", err)
	}
	for _, d := range []string{dir, cfg.DataDir, cfg.LogDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "minipanel.db"))
	if err != nil {
		return nil, fmt.Errorf("打开数据库: %w", err)
	}
	caps, err := plat.Detect()
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("能力探测: %w", err)
	}
	_, statErr := os.Stat(config.Path(dir))
	return &env{plat: plat, dir: dir, cfg: cfg, st: st, caps: caps,
		log: newLogger(), exists: statErr == nil}, nil
}

func newLogger() *slog.Logger {
	lvl := slog.LevelInfo
	if os.Getenv("MINI_PANEL_DEBUG") == "1" {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// ---- serve -----------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	bind := fs.String("bind", "", "覆盖监听地址（如 127.0.0.1）")
	port := fs.Int("port", 0, "覆盖监听端口")
	noTLS := fs.Bool("insecure-no-tls", false, "关闭面板 TLS（仅允许回环监听时接收口令）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()
	if *bind != "" {
		e.cfg.Bind = *bind
	}
	if *port != 0 {
		e.cfg.Port = *port
	}
	if *noTLS {
		e.cfg.TLS = false
	}

	// First run does the init inline: an operator who just starts the binary
	// should not have to know that a separate setup command exists.
	if !e.exists {
		if err := initialize(e, true, true); err != nil {
			return err
		}
	}

	// A panel that refuses credentials is the intended outcome here, not a
	// malfunction — but it is useless until the operator knows why.
	if !e.cfg.TLS && !isLoopbackBind(e.cfg.Bind) {
		e.log.Warn("TLS 已关闭且监听地址可被外部访问：为保证口令不明文传输，登录接口将一律拒绝。"+
			"如需本地调试，请使用 --bind 127.0.0.1。", "bind", e.cfg.Bind)
	}

	certFile, keyFile := "", ""
	if e.cfg.TLS {
		certFile, keyFile, err = sec.EnsureSelfSignedTLS(e.cfg.DataDir, certHosts(e.cfg))
		if err != nil {
			return fmt.Errorf("准备面板证书: %w", err)
		}
	}

	// The entrance lives in panel.json, but the UI shows it as a setting; keep
	// the two readings consistent instead of having a *second* source of truth.
	if err := e.st.SetSetting("panel.entrance", e.cfg.Entrance); err != nil {
		return err
	}
	if tp, _ := e.st.GetSetting("panel.trust_proxy"); tp == "true" {
		api.SetTrustProxy(true)
		e.log.Warn("X-Forwarded-For 已被信任：仅当面板真的位于自有反代之后时才应开启")
	}

	srv := api.New(e.cfg, e.st, e.plat, e.caps, audit.New(e.st),
		sec.NewLimiter(e.cfg.LoginLimit, time.Minute), e.log)

	httpSrv := &http.Server{
		Addr:    e.cfg.Addr(),
		Handler: srv.Handler(),
		// No global WriteTimeout: M4's terminal websocket would be cut by it.
		// Header and idle bounds are what stop a slow-loris style stall.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(e.log.Handler(), slog.LevelWarn),
	}
	if e.cfg.TLS {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	ln, err := net.Listen("tcp", e.cfg.Addr())
	if err != nil {
		return fmt.Errorf("监听 %s: %w", e.cfg.Addr(), err)
	}

	go func() {
		for _, line := range bannerLines(e) {
			e.log.Info(line)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		var serr error
		if e.cfg.TLS {
			serr = httpSrv.ServeTLS(ln, certFile, keyFile)
		} else {
			serr = httpSrv.Serve(ln)
		}
		if serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			errCh <- serr
			return
		}
		errCh <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startACMERenewal(ctx, e)
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		e.log.Info("收到退出信号，正在关闭")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("关闭: %w", err)
		}
		return nil
	}
}

// acmeRenewEvery is the background scan interval. Certificates are checked, not
// blindly renewed: only ACME-issued ones inside the thirty-day window are touched.
const acmeRenewEvery = 12 * time.Hour

// startACMERenewal starts the only background task this milestone adds. It is
// deliberately tied to the serve context: the same SIGTERM that stops HTTP also
// cancels a challenge halfway through, and the issuer removes the token on the
// way out. Manual and self-signed certificates are never selected.
func startACMERenewal(ctx context.Context, e *env) {
	sp, ok := e.plat.(platform.SiteProvider)
	if !ok {
		return
	}
	m, ok := sp.Sites()
	if !ok || m == nil {
		return
	}
	am, ok := m.(platform.SiteACMEManager)
	if !ok || am == nil {
		return
	}
	e.log.Info("ACME 自动续期已启用", "scan_every", acmeRenewEvery.String(), "renew_before", "720h")
	go func() {
		// Give the listener a moment to settle, then scan immediately rather
		// than waiting twelve hours to notice a certificate that is already
		// inside the renewal window.
		t := time.NewTimer(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			for _, a := range am.RenewDueACME(ctx) {
				switch {
				case a.Error != "" && ctx.Err() == nil:
					e.log.Error("ACME 续期失败", "site", a.Name, "error", a.Error)
				case a.Renewed:
					e.log.Info("ACME 证书已续期", "site", a.Name)
				}
			}
			t.Reset(acmeRenewEvery)
		}
	}()
}

// isLoopbackBind mirrors the check the API makes, so the warning and the
// refusal cannot disagree.
func isLoopbackBind(bind string) bool {
	if bind == "localhost" {
		return true
	}
	ip := net.ParseIP(bind)
	return ip != nil && ip.IsLoopback()
}

// certHosts lists what the self-signed panel certificate must cover: everything
// already configured plus every address the host actually has, so moving the
// server's IP regenerates the cert instead of breaking the login page.
func certHosts(cfg *config.Config) []string {
	set := map[string]bool{}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	for _, h := range cfg.Hosts {
		add(h)
	}
	add("localhost")
	add("127.0.0.1")
	if hn, err := os.Hostname(); err == nil {
		add(hn)
	}
	if ip := net.ParseIP(cfg.Bind); ip != nil && !ip.IsUnspecified() {
		add(cfg.Bind)
	}
	// Interface addresses come back as "10.0.0.5/24"; only the bare form is a
	// legal SAN entry.
	if ifas, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifas {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			// Mask bits are not part of a SAN entry; link-local addresses are not
			// reachable from a browser, so they would only churn the cert.
			if ip := ipn.IP; !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() {
				add(ip.String())
			}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	return out
}

// ---- init ------------------------------------------------------------------

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	bind := fs.String("bind", "", "监听地址（默认 0.0.0.0；调试建议 127.0.0.1）")
	port := fs.Int("port", 0, "监听端口（默认 29080）")
	noTLS := fs.Bool("insecure-no-tls", false, "关闭面板 TLS（仅允许回环监听时接收口令）")
	entrance := fs.String("entrance", "", "指定安全入口路径（留空则随机生成；--entrance - 表示关闭入口）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("init 不接受位置参数，多余的是 %q（用 minipanel init -h 看选项）", strings.Join(fs.Args(), " "))
	}
	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()
	// init is the one command that is allowed to write bootstrap values, and it
	// writes them before anything is listening — so applying the flags here is
	// safe, whereas making the same keys API-writable would let a stolen session
	// move the panel out from under its operator.
	if *bind != "" {
		e.cfg.Bind = *bind
	}
	if *port != 0 {
		e.cfg.Port = *port
	}
	if *noTLS {
		e.cfg.TLS = false
	}
	if *entrance != "" {
		if *entrance == "-" {
			e.cfg.Entrance = ""
		} else {
			p := *entrance
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			if err := sec.ValidateEntrance(p); err != nil {
				return err
			}
			e.cfg.Entrance = p
		}
	}
	return initialize(e, false, *entrance == "")
}

// initialize provisions the entrance and certificate and writes panel.json.
// generateEntrance is not implied by "entrance is empty": an operator can ask
// for no entrance at all (--entrance -), and that decision must survive rather
// than be silently overwritten by a freshly random path.
func initialize(e *env, firstRun, generateEntrance bool) error {
	if generateEntrance && e.cfg.Entrance == "" {
		e.cfg.Entrance = sec.NewEntrance()
	}
	if err := e.cfg.Save(e.dir); err != nil {
		return fmt.Errorf("写入配置: %w", err)
	}
	if e.cfg.TLS {
		if _, _, err := sec.EnsureSelfSignedTLS(e.cfg.DataDir, certHosts(e.cfg)); err != nil {
			return fmt.Errorf("生成面板证书: %w", err)
		}
	}
	if err := e.st.SetSetting("panel.entrance", e.cfg.Entrance); err != nil {
		return err
	}
	e.log.Info("配置已写入", "file", config.Path(e.dir), "mode", "0600")
	for _, line := range bannerLines(e) {
		fmt.Println("  " + line)
	}
	if firstRun {
		fmt.Println("\n  下一步：在浏览器打开上面的地址；首次登录会要求创建管理员账号。")
		fmt.Println("  忘记入口或口令时，在本机执行 minipanel doctor / minipanel passwd <user>。")
	}
	return nil
}

// bannerLines is the operator-facing summary printed on init and on start. It is
// the equivalent of BaoTa's `bt default` panel, built from typed values only.
func bannerLines(e *env) []string {
	cfg, caps := e.cfg, e.caps
	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d%s", scheme, displayHost(cfg.Bind), cfg.Port, cfg.Entrance)
	has, _ := e.st.HasAnyUser()
	state := "未创建"
	if has {
		state = "已创建"
	}
	return []string{
		"Mini Panel " + build.Version + " · " + caps.OS + "/" + caps.Arch + " · " + caps.OSVersion,
		"面板地址  " + url,
		"安全入口  " + orNone(cfg.Entrance) + "（未启用时任何路径都可打开登录页）",
		"TLS       " + boolCN(cfg.TLS) + " · 监听 " + cfg.Addr(),
		"未认证响应 " + fmt.Sprintf("%d", cfg.UnauthStatus) + " · 登录失败上限 " + fmt.Sprintf("%d", cfg.LoginLimit) + " 次",
		"数据目录  " + cfg.DataDir + " · 配置 " + config.Path(e.dir),
		"管理员账号 " + state + " · 配置文件权限应为 0600",
	}
}

func displayHost(bind string) string {
	if net.ParseIP(bind) != nil && !net.ParseIP(bind).IsUnspecified() {
		return bind
	}
	return "服务器IP"
}

func orNone(s string) string {
	if s == "" {
		return "（未设置）"
	}
	return s
}

func boolCN(b bool) string {
	if b {
		return "开启"
	}
	return "关闭"
}

// ---- doctor ----------------------------------------------------------------

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()

	var schemaVer string
	_ = e.st.DB().QueryRow(`SELECT value FROM schema_meta WHERE key='version'`).Scan(&schemaVer)
	var users, sessions, auditRows int
	_ = e.st.DB().QueryRow(`SELECT COUNT(1) FROM users`).Scan(&users)
	_ = e.st.DB().QueryRow(`SELECT COUNT(1) FROM sessions WHERE revoked=0 AND expires_at>strftime('%s','now')`).Scan(&sessions)
	_ = e.st.DB().QueryRow(`SELECT COUNT(1) FROM audit`).Scan(&auditRows)
	dbBytes := fileSize(filepath.Join(e.cfg.DataDir, "minipanel.db"))

	certSummary := "未启用 TLS"
	if e.cfg.TLS {
		info := sec.ReadCert(sec.CertPath(e.cfg.DataDir))
		if info.Err != nil {
			return info.Err
		}
		certSummary = info.Summary
	}

	// One computation, two consumers: internal/lockout is also what
	// GET /api/v1/lockout-risks answers from, so the self-check and the 「CLI
	// 对照」page cannot tell different stories about the same switch. Doctor keeps
	// its old shape — only the switches that are actually armed right now.
	lockRisks := lockout.OnlyArmed(lockout.Risks(e.st, e.cfg))

	// The PHP line deliberately does not read the bitmap. It goes through
	// platform.PHPCtl, the interface M2's write side will use, so that `doctor`
	// executes the same code path a later handler will — and prints it next to
	// the capability fields the bitmap claims. TestDoctorPHPCtlLineIsTheInterface
	// pins the two against each other, which is what makes a drift a failing test
	// rather than an inconsistency an operator reads on their own box.
	phpInfo := phpProbe(e.plat)

	if *asJSON {
		out := map[string]any{
			"lockout_risks": lockRisks,
			"config_file":   config.Path(e.dir),
			"config_exists": e.exists,
			"config":        e.cfg,
			"capabilities":  e.caps,
			"site_root":     e.plat.SiteRoot(),
			"backup_root":   e.plat.BackupRoot(),
			// php_ctl_* are the PHPCtl answers, kept separate from
			// capabilities.php_versions on purpose: the test compares them, and a
			// single merged key would hide the disagreement it exists to catch.
			// The *_state keys are a second, independent claim about the same two
			// paths — "here is where the socket is" and "is anyone answering" are
			// not one sentence, and merging them is how a stopped fpm gets
			// reported as a working backend.
			"php_ctl_versions": phpInfo.versions,
			"php_pool_dir":     phpInfo.poolDir,
			"php_pool_state":   phpInfo.poolState,
			"php_socket":       phpInfo.socket,
			"php_socket_state": phpInfo.socketState,
			"php_note":         phpInfo.note,
			"schema_version":   schemaVer,
			"users":            users,
			"active_sessions":  sessions,
			"audit_rows":       auditRows,
			"db_bytes":         dbBytes,
			"certificate":      certSummary,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Println("Mini Panel 自检")
	fmt.Println("  版本        ", build.Version, "("+build.Commit+")")
	fmt.Println("  平台        ", e.caps.OS, e.caps.OSFamily, e.caps.Arch, "特权:", e.caps.IsPrivileged)
	fmt.Println("  配置文件    ", config.Path(e.dir), "存在:", e.exists)
	fmt.Println("  数据目录    ", e.cfg.DataDir, " 日志:", e.cfg.LogDir)
	fmt.Println("  站点/备份   ", e.plat.SiteRoot(), "|", e.plat.BackupRoot())
	fmt.Println("  PHP         ", phpSummary(phpInfo))
	phpMismatch := phpBitmapMismatch(e.caps, phpInfo)
	if phpMismatch != "" {
		fmt.Println("    注意：", phpMismatch)
	}
	fmt.Println("  数据库      schema v"+schemaVer, " 大小", dbBytes, "B")
	fmt.Println("  账号        用户", users, " 有效会话", sessions, " 审计", auditRows, "条")
	fmt.Println("  证书        ", certSummary)
	fmt.Println("  监听        ", e.cfg.Addr(), "TLS:", e.cfg.TLS, "未认证响应:", e.cfg.UnauthStatus)
	fmt.Println("  安全入口    ", orNone(e.cfg.Entrance))
	if e.cfg.Entrance == "" {
		fmt.Println("    提示：入口未启用，登录页对任何路径可见。执行 minipanel reset-entrance 生成。")
	}
	if users == 0 {
		fmt.Println("    提示：尚无管理员账号，面板启动后会在首次访问时要求初始化。")
	}
	// Every panel-side safety switch is also a way to lock the operator out of
	// their own machine, so the self-check names them and the matching rescue
	// command together. Anything that is armed but has no undo here is a bug.
	if len(lockRisks) > 0 {
		fmt.Println("  锁死风险    （每条都有本机自救命令，无需面板可用）")
		for _, l := range lockRisks {
			fmt.Printf("    %s：%s\n      自救：%s\n", l.Name, l.State, l.Undo)
		}
	}
	feats := make([]string, 0, len(e.caps.Features))
	for k, f := range e.caps.Features {
		if f.State == platform.StateAvailable {
			continue
		}
		feats = append(feats, k+"["+string(f.State)+"]("+f.Reason+")")
	}
	if len(feats) > 0 {
		sort.Strings(feats)
		fmt.Println("  未开放能力  ", strings.Join(feats, " "))
	}
	return nil
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// ---- passwd ----------------------------------------------------------------

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	pw := fs.String("password", "", "口令（留空则从标准输入读取）")
	// `passwd admin --password X` and `passwd --password X admin` must both work:
	// Go's flag package stops at the first positional, so pull a leading username
	// out before parsing.
	rest := args
	var lead string
	if len(rest) > 0 && rest[0] != "" && !strings.HasPrefix(rest[0], "-") {
		lead, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	name := lead
	if name == "" {
		if fs.NArg() != 1 {
			return fmt.Errorf("用法: minipanel passwd <用户名> [--password '…']")
		}
		name = fs.Arg(0)
	} else if fs.NArg() > 0 {
		return fmt.Errorf("用法: minipanel passwd <用户名> [--password '…']")
	}
	if err := sec.ValidateUsername(name); err != nil {
		return err
	}
	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()

	value := *pw
	if value == "" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			// A tty gets a real hidden prompt. Claiming "不回显" while leaving
			// echo on — which is what this function did until the wording was
			// checked against the behaviour — puts the password in the operator's
			// scrollback and on the screen.
			fmt.Print("输入新口令: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("读取口令: %w", err)
			}
			value = string(b)
		} else {
			// Piped input (echo 'x' | minipanel passwd admin): no prompt, and no
			// terminal to hide anything in.
			value = readLine(os.Stdin)
		}
	}
	value = strings.TrimRight(value, "\r\n")
	if err := sec.ValidatePassword(value); err != nil {
		return err
	}
	hash, err := sec.HashPassword(value)
	if err != nil {
		return err
	}
	u, err := e.st.UserByUsername(name)
	if errors.Is(err, sql.ErrNoRows) {
		now := time.Now().Unix()
		if err := e.st.CreateUser(&store.User{Username: name, PwHash: hash,
			CreatedAt: now, PwUpdatedAt: now, MustChangePW: true}); err != nil {
			return fmt.Errorf("创建账号: %w", err)
		}
		fmt.Printf("已创建管理员 %s（首次登录需修改口令）\n", name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取账号: %w", err)
	}
	if err := e.st.SetPassword(u.ID, hash, true); err != nil {
		return err
	}
	// A password set over the shell invalidates every existing session.
	res, err := e.st.DB().Exec(`UPDATE sessions SET revoked=1 WHERE user_id=?`, u.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	fmt.Printf("已更新 %s 的口令，作废 %d 个会话；下次登录要求修改口令。\n", name, n)
	return nil
}

func readLine(r io.Reader) string {
	br := bufio.NewReader(r)
	line, _ := br.ReadString('\n')
	return line
}

// ---- reset-entrance --------------------------------------------------------

func cmdResetEntrance(args []string) error {
	fs := flag.NewFlagSet("reset-entrance", flag.ContinueOnError)
	disable := fs.Bool("disable", false, "清除安全入口（任何路径都能打开登录页）")
	set := fs.String("set", "", "手动指定入口路径，如 /panel2026")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()

	if *disable && *set != "" {
		// Refuse the contradiction instead of resolving it: "turn it off" and
		// "set it to this" cannot both be what the operator meant, and picking
		// one silently is how a script ends up with an entrance nobody chose.
		return fmt.Errorf("--disable 与 --set 互斥，请只选一个")
	}
	switch {
	case *disable:
		e.cfg.Entrance = ""
	case *set != "":
		p := *set
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if err := sec.ValidateEntrance(p); err != nil {
			return err
		}
		e.cfg.Entrance = p
	default:
		e.cfg.Entrance = sec.NewEntrance()
	}
	if err := e.cfg.Save(e.dir); err != nil {
		return err
	}
	if err := e.st.SetSetting("panel.entrance", e.cfg.Entrance); err != nil {
		return err
	}
	fmt.Println("安全入口已更新为", orNone(e.cfg.Entrance), "— 需重启面板生效。")
	return nil
}

// ---- reset-ips -------------------------------------------------------------

// cmdResetIPs is the escape hatch for panel.ip_allowlist. The list is enforced in
// the session middleware (internal/api/server.go), which means a typo can refuse
// the very request that would fix it — a setting whose only undo was editing
// SQLite by hand is not a setting an operator should have to trust.
func cmdResetIPs(args []string) error {
	fs := flag.NewFlagSet("reset-ips", flag.ContinueOnError)
	set := fs.String("set", "", "写入新的白名单（IP 或 CIDR，多个用逗号或换行分隔）")
	clear := fs.Bool("clear", false, "清空白名单，恢复为不限制来源")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("reset-ips 不接受位置参数，多余的是 %q（用 minipanel reset-ips -h 看选项）",
			strings.Join(fs.Args(), " "))
	}
	if *clear && *set != "" {
		return fmt.Errorf("--clear 与 --set 互斥，请只选一个")
	}
	if !*clear && *set == "" {
		return fmt.Errorf("reset-ips 需要 --set <列表> 或 --clear 之一；" +
			"不带参数时什么都不做，是为了避免一条命令的笔误顺手关掉访问控制")
	}
	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()

	value := ""
	if *set != "" {
		// The same validator the API uses, so a list this command accepts is a
		// list the middleware reads the same way.
		v, err := sec.NormalizeIPAllowlist(strings.ReplaceAll(*set, ",", "\n"))
		if err != nil {
			return err
		}
		value = v
	}
	if err := e.st.SetSetting("panel.ip_allowlist", value); err != nil {
		return err
	}
	if value == "" {
		fmt.Println("IP 白名单已清空：任何来源地址都允许访问面板（仍需登录）。下一条请求就生效，不用重启面板。")
		return nil
	}
	n := strings.Count(strings.TrimRight(value, "\n"), "\n") + 1
	// Wording checked against the code, not assumed: ipAllowed() re-reads the
	// setting on every request (internal/api/server.go), so this one takes effect
	// immediately. Telling the operator to restart would leave them hunting for a
	// change that already happened — and reset-entrance, which really does need
	// one, is the reason they would suspect the message was stale.
	fmt.Printf("IP 白名单已写入 %d 条，下一条请求就生效：白名单是每次请求现读的，不用重启面板。\n", n)
	fmt.Println("提醒：确认列表里包含你此刻的来源地址，否则下一条请求就会被拒绝；" +
		"万一被挡在外面，在机器上再跑一次 minipanel reset-ips --clear。")
	return nil
}

// ---- reset-2fa -------------------------------------------------------------

// cmdReset2FA is the escape hatch for TOTP. Once totp_enabled is set, a code is
// required at login and the secret lives only in this database; without this
// command the fix for a lost phone was hand-editing the users table, which turns
// the panel's own two-factor protection into a self-inflicted outage.
func cmdReset2FA(args []string) error {
	fs := flag.NewFlagSet("reset-2fa", flag.ContinueOnError)
	user := fs.String("user", "", "账号名（默认当前唯一的管理员）")
	clear := fs.Bool("clear", false, "关闭两步验证并作废已保存的密钥")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("reset-2fa 不接受位置参数，多余的是 %q（用 minipanel reset-2fa -h 看选项）",
			strings.Join(fs.Args(), " "))
	}
	if !*clear {
		return fmt.Errorf("reset-2fa 需要显式 --clear：关闭两步验证会降低账号强度，" +
			"这条命令不做任何默认动作")
	}
	e, err := bootstrap()
	if err != nil {
		return err
	}
	defer e.st.Close()

	uname, err := targetUser(e, *user)
	if err != nil {
		return err
	}
	u, err := e.st.UserByUsername(uname)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("账号 %s 不存在", uname)
	}
	if err != nil {
		return fmt.Errorf("读取账号 %s: %w", uname, err)
	}
	if err := e.st.SetTOTP(u.ID, "", false); err != nil {
		return err
	}
	// A second factor that was just turned off should not leave behind the
	// sessions that were minted while it was on: whoever holds the phone was the
	// only one who could log in, and now anybody with the password can.
	revoked, _ := e.st.DB().Exec(`UPDATE sessions SET revoked=1 WHERE user_id=?`, u.ID)
	n, _ := revoked.RowsAffected()
	fmt.Printf("账号 %s 的两步验证已关闭，作废 %d 个会话。\n", uname, n)
	// Both halves of that sentence are live: the TOTP secret is read from the
	// users table at login and session revocation is checked per request, so no
	// restart is involved. What does have to happen is re-enabling the second
	// factor from the panel once the password works again.
	fmt.Println("口令登录现在可用（立即生效，无需重启）——登录后在面板「账号安全」里重新开启两步验证。")
	return nil
}

// targetUser resolves --user, or the single administrator when it is omitted.
// Asking "which account?" interactively would make both of these commands
// unusable from a recovery script, and there is exactly one account in practice.
func targetUser(e *env, name string) (string, error) {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name), nil
	}
	var got []string
	rows, err := e.st.DB().Query(`SELECT username FROM users ORDER BY id`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		got = append(got, s)
	}
	switch len(got) {
	case 0:
		return "", fmt.Errorf("还没有管理员账号，先跑 minipanel init")
	case 1:
		return got[0], nil
	default:
		return "", fmt.Errorf("存在 %d 个账号（%s），请用 --user 指定哪一个",
			len(got), strings.Join(got, ", "))
	}
}
