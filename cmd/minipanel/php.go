package main

import (
	"strings"

	"github.com/Lisir2002/Mini_Panel/internal/php"
	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// This file exists because `minipanel doctor` must run the code it describes.
// The PHP line below is produced by platform.PHPCtl — the same interface M2's
// site handler will call to find a pool directory and a socket — and it is
// compared against the capability bitmap on every run, so the two PHP answers in
// this binary cannot drift into telling different stories.

// phpProbeResult is what doctor prints for PHP and what `--json` exposes as the
// php_ctl_* keys. poolDir/socket are the paths PHPCtl names; poolState and
// socketState are what the filesystem and the kernel say about them at this
// instant. They are separate fields because they are separate claims, and the
// old line printed the first as if it were the second.
type phpProbeResult struct {
	versions    []string
	poolDir     string
	poolState   string
	socket      string
	socketState string
	note        string // non-empty only when the platform cannot answer at all
}

func phpProbe(plat platform.Platform) phpProbeResult {
	ctl, ok := plat.(platform.PHPCtl)
	if !ok {
		// Saying "this platform has nothing to probe" is the honest half of the
		// Windows story: its PHP answer still comes from a build tag, and printing
		// a Linux-shaped probe line there would be borrowing a fact from the wrong
		// platform.
		return phpProbeResult{note: plat.ID() + " 平台尚未实现 PHPCtl，本行没有可探测的内容"}
	}
	v, err := ctl.Versions()
	if err != nil {
		return phpProbeResult{note: "PHPCtl.Versions() 失败：" + err.Error()}
	}
	p := phpProbeResult{versions: v}
	if len(v) > 0 {
		// Discover orders versions numerically, so the last one really is the
		// newest — which is what the "最新" below then claims.
		last := v[len(v)-1]
		p.poolDir = ctl.PoolDir(last)
		p.socket = ctl.SocketPath(last)
	}
	// States are filled even for empty paths, so `--json` always carries an
	// answer to "what did you check" rather than a missing key.
	p.poolState = php.DirStatus(p.poolDir)
	p.socketState = php.SocketStatus(p.socket)
	return p
}

// poolWords and socketWords turn the state constants into what an operator
// reads. Each one says what was observed right now, never what would normally be
// there — the whole point of this line is that the path and the state are two
// different claims, and the old one printed only the first.
func poolWords(state string) string {
	switch state {
	case php.DirPresent:
		return "在"
	case php.DirAbsent:
		return "磁盘上还没有"
	case php.DirNotDir:
		return "那个名字上不是目录"
	default:
		return "这个版本没有 fpm，没有 pool 可报"
	}
}

// socketWords keeps three situations apart that a panel otherwise conflates: a
// live backend, a dead one whose file is still there, and a host where fpm was
// never installed. "Could not tell" is its own answer, because guessing idle
// would be a claim about the kernel table this process could not read.
func socketWords(state string) string {
	switch state {
	case php.SocketListening:
		return "内核里有进程在听"
	case php.SocketIdle:
		return "文件在但内核里没人听，fpm 大概是停了"
	case php.SocketAbsent:
		return "文件不存在"
	case php.SocketNotSocket:
		return "那里是个普通文件，不是 socket"
	case php.SocketUnknown:
		return "读不到 /proc/net/unix，判断不了"
	default:
		return "这个版本没有 fpm，没有 socket 可报"
	}
}

func phpSummary(p phpProbeResult) string {
	if p.note != "" {
		return p.note
	}
	root := ""
	if r := php.Root(); r != "" {
		root = "（MINI_PANEL_ROOT=" + r + "）"
	}
	if len(p.versions) == 0 {
		return "未检测到可运行的 PHP" + root
	}
	return strings.Join(p.versions, " ") + "，最新 " + p.versions[len(p.versions)-1] +
		"：pool " + sayPath(p.poolDir, poolWords(p.poolState)) +
		"；socket " + sayPath(p.socket, socketWords(p.socketState)) +
		"——路径来自 PHPCtl，状态是此刻现场读的" + root
}

// sayPath keeps "no path" from reading like a path that happens to be empty: the
// state alone is the sentence when PHPCtl gave nothing to check.
func sayPath(path, state string) string {
	if path == "" {
		return state
	}
	return path + " " + state
}

// phpBitmapMismatch compares the two PHP answers the self-check has. It prints
// only on a real contradiction; "" means the operator sees no 注意 line.
func phpBitmapMismatch(caps *platform.Capabilities, p phpProbeResult) string {
	if p.note != "" {
		return ""
	}
	if strings.Join(caps.PHPVersions, " ") != strings.Join(p.versions, " ") {
		return "能力位图 php_versions=[" + strings.Join(caps.PHPVersions, " ") +
			"] 与 PHPCtl.Versions()=[" + strings.Join(p.versions, " ") +
			"] 不一致：要么两次探测之间环境变了，要么有一处不再是现场探测。这是本项目的缺陷，请附本行提 issue。"
	}
	state := caps.State(platform.FeatPHP)
	if len(p.versions) > 0 && state == platform.StateUnavailable {
		return "探测到 PHP " + strings.Join(p.versions, " ") +
			"，但 php 能力位仍是 unavailable 而不是 degraded——理由与现场不符，这是本项目的缺陷，请提 issue。"
	}
	if len(p.versions) == 0 && state == platform.StateAvailable {
		return "php 能力位是 available，但 PHPCtl 探测不到任何版本：这一项不是本机此刻真能做的事。请提 issue。"
	}
	// The kernel table and the bitmap are two independent reads of the same
	// backend, and they disagree in a way that matters: a listening socket while
	// php_modes has no fpm means either fpm was started from somewhere this
	// discovery does not model, or one of the two readings drifted. Either way the
	// operator should see the sentence rather than pick a site target and get 502.
	if p.socketState == php.SocketListening && !hasMode(caps.PHPModes, platform.PHPModeFPM) {
		return "PHPCtl 报的 socket " + p.socket + " 在内核里是 LISTEN 状态，但位图 php_modes=[" +
			joinModes(caps.PHPModes) + "] 里没有 fpm：两边对同一个后端的判断不一致。" +
			"可能是 fpm 从这套探测没有建模的路径启动（非 Debian 布局），也可能是某一侧不再是现场读取。请把本行一起贴出来。"
	}
	return ""
}

// joinModes exists because php_modes is a typed slice and an empty one must read
// as "[]" rather than as nothing at all.
func joinModes(modes []platform.PHPRuntimeMode) string {
	out := make([]string, 0, len(modes))
	for _, m := range modes {
		out = append(out, string(m))
	}
	return strings.Join(out, " ")
}

// hasMode is the membership test the two PHP answers share.
func hasMode(modes []platform.PHPRuntimeMode, want platform.PHPRuntimeMode) bool {
	for _, m := range modes {
		if m == want {
			return true
		}
	}
	return false
}
