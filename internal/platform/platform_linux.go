//go:build linux

package platform

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	mpacme "github.com/Lisir2002/Mini_Panel/internal/acme"
	"github.com/Lisir2002/Mini_Panel/internal/nginx"
	"github.com/Lisir2002/Mini_Panel/internal/php"
)

type linuxPlatform struct{}

func newPlatform() Platform { return linuxPlatform{} }

// PHPCtl is implemented by the Linux platform from M2 onward: internal/php does
// the discovery, so the three methods below answer from the host rather than
// from a build tag. Asserting it here means a signature change breaks the build
// instead of leaving a handler to type-assert at runtime.
var _ PHPCtl = linuxPlatform{}

func (linuxPlatform) ID() string { return "linux" }

func (linuxPlatform) ConfigDir() string  { return rooted("/etc/minipanel") }
func (linuxPlatform) DataDir() string    { return rooted("/var/lib/minipanel") }
func (linuxPlatform) LogDir() string     { return rooted("/var/log/minipanel") }
func (linuxPlatform) SiteRoot() string   { return envOr("MINI_PANEL_SITE_ROOT", "/www/wwwroot") }
func (linuxPlatform) BackupRoot() string { return envOr("MINI_PANEL_BACKUP_ROOT", "/www/backup") }

// rooted lets a developer relocate the whole footprint with MINI_PANEL_ROOT,
// which is how the unit tests and this repo's demo run avoid touching /etc.
func rooted(p string) string {
	if r := os.Getenv("MINI_PANEL_ROOT"); r != "" {
		return strings.TrimRight(r, "/") + p
	}
	return p
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Versions, PoolDir and SocketPath are PHPCtl. Versions re-probes the host on
// every call instead of reading a cached bitmap, because a panel that answers
// "which PHP versions exist" from startup-time data lies the moment the operator
// installs one, and discovery is cheap enough to run live.
//
// PoolDir and SocketPath are the other half of the promise and they answer a
// different question: they name where a version's pool directory and listen
// socket are *supposed* to be, which is what the write side needs and is not the
// same claim as "it is there". Existence and liveness are asked separately, via
// php.DirStatus / php.SocketStatus — and `minipanel doctor` prints both answers
// next to each other, so a stopped php-fpm on a host that still has the file
// cannot be read as a working backend.
func (linuxPlatform) Versions() ([]string, error) {
	installs, _ := php.Discover()
	return php.Versions(installs), nil
}

func (linuxPlatform) PoolDir(version string) string { return php.PoolDir(version) }

func (linuxPlatform) SocketPath(version string) string { return php.SocketPath(version) }

// nginxRoot is the tree the site writer manages. The env override exists for
// the same reason MINI_PANEL_SITE_ROOT does: `make run` must be able to point
// at a scratch directory instead of /etc/nginx.
func nginxRoot() string { return envOr("MINI_PANEL_NGINX_ROOT", "/etc/nginx") }

// WebServer and Sites are the M2 provider seam. Both re-detect on every call
// instead of caching a manager at startup, so the provider follows a host
// that gains or loses nginx. The capability bitmap is computed once at panel
// start, so a fresh install still needs a restart before the site page is
// exposed; detection is cheap, and the provider itself never caches a lie.
func (linuxPlatform) WebServer() (WebServerCtl, bool) {
	m, err := nginx.NewWithCertDir(nginxRoot(), linuxPlatform{}.SiteRoot(), rooted("/etc/minipanel/certs"))
	if err != nil {
		return nil, false
	}
	return linuxWebServer{m: m}, true
}

func (linuxPlatform) Sites() (SiteManager, bool) {
	m, err := nginx.NewWithCertDir(nginxRoot(), linuxPlatform{}.SiteRoot(), rooted("/etc/minipanel/certs"))
	if err != nil {
		return nil, false
	}
	// Writing /etc/nginx and reloading the server needs root. Reporting the
	// capability without this check is how a panel ends up with a page whose
	// every button returns EACCES.
	if os.Geteuid() != 0 {
		return nil, false
	}
	return linuxSites{m: m}, true
}

type linuxWebServer struct{ m *nginx.Manager }

func (w linuxWebServer) Name() WebServerName { return WebNginx }

func (w linuxWebServer) TestConfig() error {
	_, err := w.m.TestConfig()
	return err
}

func (w linuxWebServer) Reload() error {
	_, err := w.m.Reload()
	return err
}

func (w linuxWebServer) Restart() error {
	_, err := w.m.Restart()
	return err
}

// linuxSites converts between the platform-neutral rows and the nginx writer.
// Error identity is preserved across the boundary via the platform sentinels,
// so the HTTP layer never imports internal/nginx.
type linuxSites struct{ m *nginx.Manager }

func (l linuxSites) List() ([]SiteInfo, error) {
	sites, err := l.m.List()
	if err != nil {
		return nil, err
	}
	out := make([]SiteInfo, 0, len(sites))
	for _, s := range sites {
		out = append(out, toSiteInfo(s))
	}
	return out, nil
}

func (l linuxSites) Create(spec SiteSpec) (SiteInfo, error) {
	s, err := l.m.Create(nginx.Spec{Name: spec.Name, Domains: spec.Domains, Root: spec.Root})
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	return toSiteInfo(s), nil
}

func (l linuxSites) Delete(name string) (SiteInfo, error) {
	s, err := l.m.Delete(name)
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	return toSiteInfo(s), nil
}

func (l linuxSites) SetSelfSigned(name string, redirect bool) (SiteInfo, error) {
	s, err := l.m.SetSelfSigned(name, redirect)
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	return toSiteInfo(s), nil
}

func (l linuxSites) SetCertificate(name, certPEM, keyPEM string, redirect bool) (SiteInfo, error) {
	s, err := l.m.SetCertificate(name, certPEM, keyPEM, redirect)
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	return toSiteInfo(s), nil
}

func (l linuxSites) ClearCertificate(name string) (SiteInfo, error) {
	s, err := l.m.ClearCertificate(name)
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	return toSiteInfo(s), nil
}

// acmeOps serialises certificate issuance. Two HTTP-01 orders touching the same
// site root or the same account key would otherwise race on challenge files and
// account registration; the panel has no use for parallel issuance on one host.
var acmeOps sync.Mutex

func (l linuxSites) ObtainACME(ctx context.Context, name string, redirect bool) (SiteInfo, error) {
	acmeOps.Lock()
	defer acmeOps.Unlock()
	return l.obtainACME(ctx, name, redirect)
}

// obtainACME assumes acmeOps is held. It reads the site twice on purpose: the
// first read exists to reject wildcards before touching a config, and the
// second (inside PrepareACME) is the state after the challenge-serving rewrite.
func (l linuxSites) obtainACME(ctx context.Context, name string, redirect bool) (SiteInfo, error) {
	pre, err := l.m.Get(name)
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	for _, d := range pre.Domains {
		if strings.HasPrefix(d, "*.") {
			return SiteInfo{}, fmt.Errorf("%w：%s 是通配符，需要 DNS-01；当前只能上传通配符证书", ErrACMEUnsupported, d)
		}
	}
	if _, err := l.m.PrepareACME(name); err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	issuer, err := newACMEIssuer()
	if err != nil {
		return SiteInfo{}, fmt.Errorf("%w：%v", ErrACMEFailed, err)
	}
	creds, err := issuer.Issue(ctx, pre.Domains, pre.Root)
	if err != nil {
		return SiteInfo{}, mapACMEErr(err)
	}
	s, err := l.m.SetACMECertificate(name, string(creds.CertPEM), string(creds.KeyPEM), redirect)
	if err != nil {
		return SiteInfo{}, mapNginxErr(err)
	}
	return toSiteInfo(s), nil
}

// RenewDueACME walks only certificates whose marker says ACME issued them. A
// manually uploaded or self-signed certificate is never silently replaced: it
// may be the operator's only copy of a wildcard or internal CA certificate.
func (l linuxSites) RenewDueACME(ctx context.Context) []ACMEAttempt {
	sites, err := l.m.List()
	if err != nil {
		return []ACMEAttempt{{Name: "*", Error: "读取站点列表失败：" + err.Error()}}
	}
	now := time.Now()
	out := []ACMEAttempt{}
	for _, s := range sites {
		if err := ctx.Err(); err != nil {
			return append(out, ACMEAttempt{Name: "*", Error: "续期被中断：" + err.Error()})
		}
		if s.TLS == nil || !s.TLS.ACME {
			continue
		}
		if !mpacme.RenewalDue(s.TLS.NotAfter, now) {
			continue
		}
		acmeOps.Lock()
		_, err := l.obtainACME(ctx, s.Name, s.TLS.Redirect)
		acmeOps.Unlock()
		a := ACMEAttempt{Name: s.Name, Renewed: err == nil}
		if err != nil {
			a.Error = err.Error()
		}
		out = append(out, a)
	}
	return out
}

func newACMEIssuer() (*mpacme.Issuer, error) {
	dir := envOr("MINI_PANEL_ACME_DIRECTORY", mpacme.DefaultDirectoryURL)
	key := filepath.Join(rooted("/etc/minipanel/acme"), "account.key")
	return mpacme.NewIssuer(dir, key, envOr("MINI_PANEL_ACME_CA_FILE", ""))
}

func mapACMEErr(err error) error {
	switch {
	case errors.Is(err, mpacme.ErrUnsupported):
		detail := strings.TrimPrefix(err.Error(), mpacme.ErrUnsupported.Error())
		detail = strings.TrimPrefix(detail, "：")
		if detail == "" {
			return fmt.Errorf("%w", ErrACMEUnsupported)
		}
		return fmt.Errorf("%w：%s", ErrACMEUnsupported, detail)
	case errors.Is(err, mpacme.ErrFailed):
		detail := strings.TrimPrefix(err.Error(), mpacme.ErrFailed.Error())
		detail = strings.TrimPrefix(detail, "：")
		if detail == "" {
			return fmt.Errorf("%w", ErrACMEFailed)
		}
		return fmt.Errorf("%w：%s", ErrACMEFailed, detail)
	default:
		return err
	}
}

func toSiteInfo(s nginx.Site) SiteInfo {
	out := SiteInfo{
		Name: s.Name, Domains: s.Domains, Root: s.Root,
		ConfigPath: s.ConfigPath, Enabled: s.Enabled, CreatedAt: s.CreatedAt,
	}
	if s.TLS != nil {
		out.TLS = &SiteTLSInfo{
			Enabled: s.TLS.Enabled, Redirect: s.TLS.Redirect, SelfSigned: s.TLS.SelfSigned, ACME: s.TLS.ACME,
			CertPath: s.TLS.CertPath, KeyPath: s.TLS.KeyPath, NotAfter: s.TLS.NotAfter, Error: s.TLS.Error,
		}
	}
	return out
}

func mapNginxErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, nginx.ErrExists):
		return fmt.Errorf("%w", ErrSiteExists)
	case errors.Is(err, nginx.ErrNotFound):
		return fmt.Errorf("%w", ErrSiteMissing)
	case errors.Is(err, nginx.ErrTLSInvalid):
		// The nginx layer already prefixes its errors with ErrTLSInvalid. Wrap
		// only the detail, or the operator sees the same sentence twice.
		detail := strings.TrimPrefix(err.Error(), nginx.ErrTLSInvalid.Error())
		detail = strings.TrimPrefix(detail, "：")
		if detail == "" {
			return fmt.Errorf("%w", ErrSiteTLSInvalid)
		}
		return fmt.Errorf("%w：%s", ErrSiteTLSInvalid, detail)
	case errors.Is(err, nginx.ErrInvalid):
		return fmt.Errorf("%w：%v", ErrSiteInvalid, err)
	case errors.Is(err, nginx.ErrConfigRejected):
		return fmt.Errorf("%w：%v", ErrSiteRefused, err)
	default:
		return err
	}
}

func (p linuxPlatform) Detect() (*Capabilities, error) {
	c := newBase()
	c.OSFamily = osFamily()
	c.OSVersion = osVersion(c.OSFamily)
	c.IsPrivileged = os.Geteuid() == 0
	c.Hostname = hostname()

	// Permissions and PHPExtInstall describe the mechanism the host offers; they
	// are facts. The matching *features* stay denied until the code that would
	// use them ships, because "chmod exists" is not the same as "this panel can
	// manage file permissions", and "phpize is installed" is not "extension
	// install works". Reporting the mechanism as the feature is how a UI ends up
	// with a clickable button over an empty handler.
	c.Permissions = "posix"

	c.ReloadMode = ReloadSIGHup

	if have("nginx") != "" || have("openresty") != "" {
		c.WebServers = append(c.WebServers, WebNginx)
		if have("openresty") != "" {
			c.WebServers = append(c.WebServers, WebOpenResty)
		}
	}
	if have("apachectl") != "" || have("httpd") != "" {
		c.WebServers = append(c.WebServers, WebApache)
	}

	// M2 third slice: site creation is available only when the host has an
	// nginx installation the writer recognises and the process can actually
	// write there. The branches are kept apart because the UI has to be able
	// to say "no web server" apart from "nginx present, not root" apart from
	// "Apache here, the write provider is nginx-only" — three different
	// operator actions, and one shared "not supported" sentence would hide
	// which one applies.
	hasNginx := false
	for _, w := range c.WebServers {
		if w == WebNginx || w == WebOpenResty {
			hasNginx = true
		}
	}
	_, siteErr := nginx.New(nginxRoot(), p.SiteRoot())
	switch {
	case !hasNginx && len(c.WebServers) > 0:
		c.Deny(FeatWebSite, "本机检测到 Apache；站点写入 Provider 当前只实现了 nginx（M2 后续片）")
		c.Deny(featSiteWrite, "站点写入 Provider 当前只实现了 nginx（M2 后续片）")
	case !hasNginx:
		c.Deny(FeatWebSite, "本机未检测到 nginx / openresty，站点创建需要一份可写的 nginx 配置目录")
		c.Deny(featSiteWrite, "站点写入需要 nginx；本机没有可管理的 Web 服务器")
	case siteErr != nil:
		c.Deny(FeatWebSite, "检测到 nginx，但"+siteErr.Error()+"；站点写入需要一个可识别的配置目录")
		c.Deny(featSiteWrite, "站点写入需要可识别的 nginx 配置目录："+siteErr.Error())
	case !c.IsPrivileged:
		why := "已检测到 nginx，但面板进程不是 root，无法写配置目录或 reload nginx"
		c.Degrade(FeatWebSite, why, "以 root 身份运行面板（systemd 服务默认即为 root）", "minipanel doctor 的 site 行")
		c.Degrade(featSiteWrite, why, "以 root 身份运行面板", "minipanel doctor 的 site 行")
	default:
		c.Allow(FeatWebSite)
		c.Allow(featSiteWrite)
		// All three certificate paths ship in this binary: self-signed, uploaded,
		// and ACME HTTP-01 with automatic renewal. Wildcards still require an
		// uploaded certificate because HTTP-01 cannot prove them; that is a
		// limitation of the challenge type, not a missing certificate feature,
		// and the site page names it next to the ACME choice.
		c.Allow(FeatSSL)
	}

	switch {
	case have("ufw") != "":
		c.Firewall = FirewallUFW
	case have("firewall-cmd") != "":
		c.Firewall = FirewallFirewalld
	case have("nft") != "":
		c.Firewall = FirewallNftables
	}
	// Both branches deny, for different reasons: the UI must be able to tell
	// "no firewall software on this host" apart from "firewall present, write
	// provider not shipped yet".
	if c.Firewall == FirewallNone {
		c.Deny(FeatFirewall, "未检测到 ufw / firewall-cmd / nft 任一后端，本机没有可管理的防火墙")
	} else {
		c.Deny(FeatFirewall, "当前版本只读展示后端状态；规则写入 Provider 在 M4 交付")
	}

	if have("systemctl") != "" && dirExists("/run/systemd/system") {
		c.ServiceManager = "systemd"
	}
	switch {
	case have("apt-get") != "":
		c.PackageManager = "apt"
	case have("dnf") != "":
		c.PackageManager = "dnf"
	case have("yum") != "":
		c.PackageManager = "yum"
	case have("zypper") != "":
		c.PackageManager = "zypper"
	}
	if have("crontab") != "" {
		c.Schedulers = append(c.Schedulers, SchedCrontab)
	}
	c.SupportsSubSecondCron = true

	// PHP is the first capability in this bitmap whose answer comes from the host
	// rather than from the build tag. Up to this slice the three lines that
	// replaced the ones below were unconditional: `php_modes = [fpm]` and
	// `php_ext_install = [package, source]` on every Linux box, including the
	// cli-only one that has neither php-fpm nor phpize. That is the exact shape of
	// lie that later becomes a clickable nothing, and it is why the M2 rule in
	// docs/里程碑.md requires site/php/ssl to be set from Detect() evidence only.
	//
	// The feature stays short of `available` regardless: discovering a runtime is
	// not the same as serving a site through it, and the pool/vhost write path
	// ships later in M2. What changed is that "short of" now says *what* is
	// missing, from evidence — which is what docs/功能设计.md §4.1's `degraded`
	// row is for.
	installs, unreadable := php.Discover()
	c.PHPVersions = php.Versions(installs)
	fpm, cgi := php.Modes(installs)
	if fpm {
		c.PHPModes = append(c.PHPModes, PHPModeFPM)
	}
	if cgi {
		c.PHPModes = append(c.PHPModes, PHPModeCGI)
	}
	if c.PackageManager != "none" {
		c.PHPExtInstall = append(c.PHPExtInstall, ExtFromPackage)
	}
	if have("phpize") != "" {
		c.PHPExtInstall = append(c.PHPExtInstall, ExtFromSource)
	}
	phpVerify := "重跑 minipanel doctor 的 php 行，或读 GET /api/v1/capabilities 的 php_modes / php_versions"
	phpSeen := "检测到 PHP " + strings.Join(c.PHPVersions, "、")
	switch {
	case len(installs) == 0:
		// No runtime at all: this stays a plain denial, because there is no
		// "main path works" claim to make and a static-site box is a valid answer.
		c.Deny(FeatPHP, phpGap("本机未检测到可运行的 PHP", unreadable)+
			"。站点创建与 fpm 配置生成在 M2 交付，纯静态站点不受影响")
	case !fpm && !cgi:
		// The sentence names only what discovery proved. It does not say "只有
		// cli", because a version can be detected from its binary with no SAPI
		// tree at all, and an over-specific reason is a new kind of lie.
		c.Degrade(FeatPHP, phpGap(phpSeen+"，但没有检测到 fpm 或 cgi 后端，站点没有可执行 PHP 的处理器", unreadable),
			"", phpVerify)
	default:
		c.Degrade(FeatPHP, phpGap(phpSeen+" 的 "+phpModeWords(fpm, cgi)+"，版本与 pool 目录已可读；把站点绑定到某个版本的写入路径在 M2 交付", unreadable),
			"", phpVerify)
	}

	// Detection is a fact; the page that would manage it is M4 work. Allowing the
	// feature here because sshd happens to exist is precisely how a panel ends up
	// shipping a button with no code behind it.
	if have("sshd") != "" || dirExists("/run/sshd") {
		c.RemoteAccess = append(c.RemoteAccess, AccessSSH)
		c.Deny(FeatSSHManager, "本机已检测到 sshd；SSH 端口/密钥/登录策略管理页在 M4 交付")
	}
	return c, nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// phpGap appends the binaries discovery found but could not version, so a reason
// never claims "there is no PHP here" next to a /usr/bin/php that merely would
// not answer. Empty list, empty suffix.
func phpGap(head string, unreadable []string) string {
	if len(unreadable) == 0 {
		return head
	}
	return head + "；另有 " + strconv.Itoa(len(unreadable)) +
		" 个 PHP 二进制存在但无法确定版本：" + strings.Join(unreadable, " ")
}

// phpModeWords names the detected handler backends in one phrase, using only
// what Modes() proved.
func phpModeWords(fpm, cgi bool) string {
	switch {
	case fpm && cgi:
		return "fpm 与 cgi"
	case fpm:
		return "fpm"
	default:
		return "cgi"
	}
}

// osFamily maps /etc/os-release ID and ID_LIKE onto our small family set. The
// family decides which package backend and PHP repository we will use in M2.
func osFamily() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	id, like := "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			like = v
		}
	}
	for _, tok := range strings.Fields(id + " " + like) {
		switch tok {
		case "ubuntu", "debian", "mint":
			return "debian"
		case "rhel", "fedora", "centos", "almalinux", "rocky":
			return "rhel"
		case "suse", "sles", "opensuse":
			return "suse"
		case "kylin", "uos", "anolis", "alinux":
			return "cn-enterprise"
		}
	}
	if id != "" {
		return id
	}
	return "unknown"
}

func osVersion(family string) string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return family
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return family
}
