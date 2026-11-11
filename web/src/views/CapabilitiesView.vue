<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { store } from "../store";

// key 必须与后端常量逐一对齐：internal/platform/capabilities.go 的 Feat* 与
// internal/platform/detect.go 的 feat*（site_write / php_version_switch /
// firewall_write / service_write）。写错一个字母，那一行就会变成"灰但没理由"，
// 所以 TestUIDeclaresEveryCapabilityKey 会拿后端 key 清单逐个核对这份表。
const FEATS = [
  ["site", "网站"], ["site_write", "网站写入"], ["php", "PHP 多版本"],
  ["php_version_switch", "切换 PHP 版本"], ["php_ext_source", "PHP 源码编译扩展"],
  ["ssl", "SSL / ACME"], ["database", "数据库"], ["backup", "备份"],
  ["firewall", "防火墙"], ["firewall_write", "防火墙写入"], ["cron", "计划任务"],
  ["terminal", "Web 终端"], ["monitor", "监控"], ["audit", "审计"],
  ["ssh_manager", "SSH 管理"], ["file_posix_perms", "文件权限"], ["service_write", "服务管理"],
];

// 四态只有 available 画成"可用"。degraded / unavailable / foreign 都必须带
// 后端给的那句话，缺句就是缺陷——点名，不替它编理由。
const STATE = {
  available: ["可用", "on"],
  degraded: ["部分可用", "partial"],
  unavailable: ["未开放", "off"],
  foreign: ["非面板管理", "flat"],
};
const NO_REASON = "后端未给出理由（缺陷，请报告）";
const rows = ref([]);
const mech = ref([]);
const error = ref("");

const summary = computed(() => {
  const on = rows.value.filter((r) => r.state === "available");
  return "本版本可操作：" + (on.length ? on.length + " 项（" + on.map((r) => r.name).join("、") + "）" : "0 项") +
    "；其余 " + (rows.value.length - on.length) + " 项由后端明确拒绝，理由见下表。";
});

function featRow(k, name, entry) {
  if (entry === undefined) {
    return { k, name, state: "", badge: "未上报", cls: "off", reason: "后端 bitmap 里没有 " + k + " 这一项（缺陷，请报告）" };
  }
  const st = STATE[entry.state];
  if (!st) {
    return { k, name, state: "", badge: "状态异常", cls: "off", reason: '未知 state="' + entry.state + '"（契约只有四种）' };
  }
  const reason = typeof entry.reason === "string" ? entry.reason.trim() : "";
  let text;
  if (entry.state !== "available") text = reason || NO_REASON;
  else if (reason) text = "（接口同时给出了不可用理由，前后矛盾，请报告缺陷）";
  else text = "";
  return { k, name, state: entry.state, badge: st[0], cls: st[1], reason: text, fix: entry.fix_action || "", verify: entry.verify || "" };
}

// 机制探测区只说明"这台宿主机上有什么"，一律不画可用/未开放标签：
// reload_mode=sighup 不是"现在就能重载"，那是第二张表的事。
const MECH_GROUPS = [
  ["主机名 / 架构", ["hostname", "arch"], (c) => (c.hostname || "—") + " · " + (c.arch || "—"), null],
  ["操作系统", ["os", "os_family", "os_version", "is_privileged"], (c) => (c.os || "—") + " / " + (c.os_family || "—"),
    (c) => (c.os_version || "") + (c.is_privileged ? " · 进程具备提权能力" : " · 未提权")],
  ["Web 服务", ["web_servers"], (c) => (c.web_servers || []).join(", ") || "未检测到", null],
  ["PHP 运行时", ["php_modes", "php_versions"], (c) => (c.php_modes || []).join(", ") || "未检测到 fpm / cgi",
    // 这一行必须两栏一起读：php_versions 有值而 php_modes 为空，就是"装了 PHP 但没有
    // 能执行站点的后端"。上一版只把版本号裸贴在后面，读者会以为两句话在互相打脸。
    (c) => {
      const v = (c.php_versions || []).join(" ");
      if (!v) return "未检测到 PHP 运行时";
      return "已检测到 " + v + ((c.php_modes || []).length ? "" : "，但没有能执行站点的 fpm/cgi 后端");
    }],
  ["扩展安装手段", ["php_ext_install"], (c) => (c.php_ext_install || []).join(", ") || "不支持",
    () => "只是宿主上可用的安装手段，面板能不能用看下面第二张表"],
  ["重载方式", ["reload_mode"], (c) => c.reload_mode || "none", () => "探测到的是宿主机制，本版本没有可点的重载按钮"],
  ["防火墙后端", ["firewall"], (c) => c.firewall || "未检测到", null],
  ["计划任务", ["schedulers", "supports_sub_second_cron"], (c) => (c.schedulers || []).join(", ") || "无",
    (c) => (c.supports_sub_second_cron ? "（支持秒级）" : "（不支持秒级）")],
  ["服务管理 / 包管理", ["service_manager", "package_manager"],
    (c) => (c.service_manager || "未检测到") + " / " + (c.package_manager || "未检测到"), null],
  ["远程访问", ["remote_access"], (c) => (c.remote_access || []).map((x) => (x && x.kind ? x.kind : x)).join(", ") || "无", null],
  ["数据库引擎", ["database_engines"], (c) => (c.database_engines || []).join(", ") || "未检测到", null],
  ["权限模型", ["permissions"], (c) => c.permissions || "未检测到", null],
];

function build(c) {
  const used = new Set(["features"]);
  const m = [];
  for (const [label, keys, text, extra] of MECH_GROUPS) {
    keys.forEach((k) => used.add(k));
    m.push({ label, keys: keys.map((k) => "caps." + k).join(" · "), text: text(c), extra: extra ? extra(c) : "" });
  }
  // 后端加了新字段而这里没登记时，照样渲染并点名"前端未分区"，缺陷当场可见。
  for (const k of Object.keys(c)) {
    if (used.has(k)) continue;
    m.push({ label: k + "（前端未分区，请报告缺陷）", keys: "caps." + k, text: typeof c[k] === "object" ? JSON.stringify(c[k]) : String(c[k]), extra: "" });
    used.add(k);
  }
  mech.value = m;

  const f = c.features || {};
  const known = new Set(FEATS.map((x) => x[0]));
  const r = FEATS.map(([k, name]) => featRow(k, name, f[k]));
  for (const k of Object.keys(f)) {
    if (known.has(k)) continue;
    r.push(featRow(k, k + "（前端未登记，请报告缺陷）", f[k]));
  }
  rows.value = r;
}

onMounted(async () => {
  try { build(store.caps || (store.caps = await api("/api/v1/capabilities"))); }
  catch (e) { error.value = e.message; }
});
</script>

<template>
  <div class="mp-card">
    <h3>本机能力</h3>
    <p class="mp-note">
      下面两张表是两回事：<b>探测到的机制</b>只说明这台宿主机上有什么（装了 nginx、能发 sighup、有 apt），
      面板能不能操作它，一律看第二张 <b>capability bitmap</b>。机制字段不是功能开关，
      前端不会把 <code class="mp-code">reload_mode=sighup</code> 这类探测结果画成"现在就能重载"。
    </p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />

    <div class="mp-secttl">探测到的机制（宿主环境，不代表本版本可操作）</div>
    <table class="mp-mech">
      <tbody>
        <tr v-for="g in mech" :key="g.label" :title="g.keys">
          <th>{{ g.label }}</th>
          <td>{{ g.text }}<span v-if="g.extra" class="mp-muted mp-tiny"> · {{ g.extra }}</span></td>
        </tr>
      </tbody>
    </table>

    <div class="mp-secttl">本版本可操作的功能（capability bitmap 四态：available / degraded / unavailable / foreign）</div>
    <p class="mp-muted mp-tiny" style="margin:0 0 4px">{{ summary }}</p>
    <table class="mp-feats">
      <tbody>
        <tr v-for="r in rows" :key="r.k">
          <th :title="'features.' + r.k">{{ r.name }}</th>
          <td>
            <span class="mp-tag" :class="r.cls">{{ r.badge }}</span>
            <span v-if="r.reason" class="mp-muted"> {{ r.reason }}</span>
            <div v-if="r.fix" class="mp-muted mp-tiny">补齐：{{ r.fix }}</div>
            <div v-if="r.verify" class="mp-muted mp-tiny">复查：{{ r.verify }}</div>
          </td>
        </tr>
      </tbody>
    </table>
    <div class="mp-hint">
      补齐 / 复查是接口给出的两种可执行出口（能复制的命令、或一条只读复查路径），页面只呈现、不代跑；
      面板在这个版本没有"点一下替运维执行命令"这条路。
    </div>
  </div>
</template>

<style scoped>
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--mp-line); vertical-align: top; }
th { color: var(--mp-muted); font-weight: 500; width: 34%; }
tr:last-child th, tr:last-child td { border-bottom: 0; }
</style>
