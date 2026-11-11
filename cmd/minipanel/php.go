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
// php_ctl_* keys.
type phpProbeResult struct {
	versions []string
	poolDir  string
	socket   string
	note     string // non-empty only when the platform cannot answer at all
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
	return p
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
		"：pool " + p.poolDir + "，socket " + p.socket +
		"（路径由 PHPCtl 给出，未校验 socket 是否存活）" + root
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
	return ""
}
