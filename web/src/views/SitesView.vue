<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { store } from "../store";

// M2 第三、四、六、七、八、九、十、十一、十二、十三、十四、十五、十六、十七、十八、十九、二十、廿一、廿二：静态站点、站点证书、
// PHP 版本绑定、基础设置编辑、伪静态模板、反向代理、整站跳转、防盗链、访问密码、真实 IP 解析、
// 按路径跳转表、流量限制、分组 / 备注 / 搜索、目录列表 / 强制 HTTPS 开关、站点日志查看、自定义错误页、反向代理多上游负载均衡、CORS 跨域策略与受护栏的配置文件编辑。
// 这一页的边界与后端能力位图是同一句话，不另写一套：
//   * site / site_write 由 Detect() 现场决定（装了 nginx、进程是 root、配置目录可识别）。
//     不可用时这页只显示后端给的理由与 fix_action，不画一个点了没反应的"新建"按钮。
//   * 编辑对话框替换域名、根目录与默认文档。域名变更时后端先用现有证书校验新域名集合，
//     覆盖不了就返回 422 invalid_tls 且不写文件——页面原样显示理由，不假装保存成功。
//   * php_version_switch 只列出 php_fpm_versions；选择后由后端把版本解析成 socket。
//     socket 当前不是 listening 时，页面直接说"站点会 502"，不把配置写入说成后端可用。
//   * 伪静态列表来自 GET /sites/rewrite-presets，不是前端硬编码；模板内容固定在二进制里。
//     wordpress / laravel / thinkphp 需要已绑定 PHP，静态站点会被后端拒绝。
//   * 反向代理有两种形式，同一个对话框里切换：单目标（一个上游 URL）与多上游负载均衡
//     （最多 10 个 http://host:port 后端 + 权重 1-100 + 轮询 / ip_hash / least_conn）。
//     后端按 url.Parse 与字符白名单校验，页面不提供任何"自定义 nginx 片段"输入框。
//     两种形式互斥（都占用 location /），保存一边会在同一次事务里清掉另一边；与伪静态
//     的互斥不变，页面在两边对话框里都提示先清空一边，后端也会拒绝并把文件保持原样。
//     upstream 块必须落在 http 上下文，后端在同一次事务里写 vhost 与面板自有的 http 级
//     表文件；本机 nginx.conf 没有通配 include 时后端返回带理由的 400，页面原样显示。
//   * 整站跳转只接受一个绝对 URL、301/302 与"保留路径"开关；配置是固定的一行 return。
//     它同样占用 location /，与伪静态、反向代理三向互斥，页面和对话框都按同一句话提示。
//   * 防盗链只接受"开 / 关"与"是否放行无 Referer 请求"；扩展名表、valid_referers 参数与
//     403 都是后端常量。它是正则 location，可与伪静态共存；代理与整站跳转会让本机静态资源
//     不可达，因此两边互斥，页面在三个对话框里给同一句提示。
//   * 访问密码是固定的 HTTP Basic Auth：页面只收用户名与口令，realm、指令与 {SHA} 口令文件
//     都由后端决定，口令不会回显（对话框每次保存都要求重新输入）。它整站生效、不占用
//     location /，因此与其它站点功能共存；HTTPS 站点的 ACME 续期路径由后端自动豁免。
//   * 真实 IP 解析只接受"可信代理地址/网段列表 + X-Forwarded-For 或 X-Real-IP"；后端拒绝
//     0.0.0.0/0 与 ::/0，页面明确说只有列表里的对端才能影响来源地址。它是 server 级指令，
//     不占用 location /，与其它站点功能共存。
//   * 按路径跳转表只编辑"精确路径 + 301/302 + 绝对目标"三类字段；后端为每条规则渲染固定
//     location = 块并追加常量 $is_args$args，调用方不能提交任何 nginx 配置文本。整表替换、
//     空表清除，最多 10 条；它不占用 location /，因此与整站跳转、代理、伪静态共存。
//   * 流量限制只编辑"请求速率 + 突发 + 单 IP 连接数 + 超限状态码"四个数值字段；后端把 zone 名、
//     $binary_remote_addr 键与 10m 大小都固定下来，调用方不能提交任何 nginx 文本或自定义 zone。
//     由于 nginx 要求 limit_*_zone 落在 http 上下文，后端会在同一次"写文件 → nginx -t → reload"
//     事务里同时写站点 vhost 与一张面板自有的 http 级表文件，任一步失败两个文件一起回滚；本机
//     nginx.conf 若没有通配 include，后端返回带理由的 400，页面原样显示，不假装限流已生效。
//   * 分组与备注是唯一一项完全不碰 nginx 的站点控制：它只写进面板自己的 SQLite（site_meta 表），
//     列表按站点名 join 回来，既不进 vhost 也不进 marker，所以没有 nginx -t、没有 422。站点必须是
//     Provider 当前列出的站点，否则后端 404；搜索与分组过滤都在已加载的列表上做，不额外打后端。
//   * 目录列表是 server 级的固定 `autoindex` 开关（不占用 location /，与所有其它功能共存）；强制 HTTPS
//     只在站点已启用证书时出现，因为它翻转的就是证书接口早已携带的 tls.redirect——没有证书时后端会
//     以理由拒绝，页面也就不摆一个点了必然报错的按钮。两者都走 nginx -t → 通过才 reload，失败回滚。
//   * 站点日志是只读查看器：每个面板自有 vhost 都带固定的按站点 access_log / error_log，
//     页面只选"访问 / 错误"与行数，路径由后端派生，提交不了任何路径。文件还没产生时后端
//     返回 exists=false，页面如实说"尚无日志"，不假装读到了空文件就是成功。
//   * 自定义错误页只编辑"状态码 + 站内路径"两类字段；状态码是封闭列表
//     （400/401/403/404/405/408/500/502/503/504），路径必须以 / 开头且不含 nginx 元字符。
//     后端为每条规则渲染固定的 server 级 error_page 行，外加每个错误页路径一条精确
//     静态 location——反代 / 整站跳转站点的错误页因此仍从站点根目录提供，不会被
//     location / 吞掉；它不占用 location /，与所有站点功能共存，但路径不能与按路径
//     跳转的同名例外冲突（后端两个方向都以理由拒绝）。整表替换、空表清除，最多 10 条。
//     它只替换 nginx 本机产生的错误，反代站点的上游错误响应原样透传；错误页文件要放在
//     站点根目录下，缺失时 nginx 回退到内置错误页，页面在对话框里把这两条边界说清楚。
//   * CORS 只编辑结构化的跨域策略：来源列表（["*"] 或精确 scheme://host[:port]，最多 10 个）、
//     方法闭集（GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS，省略默认前三）、允许请求头（省略反射
//     预检请求头）、凭据开关与预检缓存秒数。后端渲染固定 server 级 add_header 加一个 OPTIONS
//     短路，不占用 location /，与所有站点功能共存；开启期间 OPTIONS 由本机直接回 204、不再
//     转发到上游，上游自带的 CORS 头也不会被隐藏——这两条边界在对话框里原话写明。
//     空来源列表清除策略，始终允许；* 与凭据开关互斥（浏览器禁止该组合，后端直接拒绝）。
//   * 配置文件编辑是有护栏的编辑器，不是文件管理器：只读写面板自有 vhost（外部文件后端
//     一律 404），GET 返回磁盘上的精确字节；保存时 `# minipanel-site:` 所有权标记行必须
//     原样保留且只有一行，删改/复制都会被后端以理由拒绝。保存仍走 nginx -t → 通过才
//     reload、失败恢复原字节。对话框把两条边界说清楚：标记行不可改（域名/根目录等用
//     对应功能页），以及任何后续面板功能写入都会按 marker 重新生成整份配置、覆盖手工
//     添加的指令——不假装手工编辑能永久生效。
//   * ssl 可用时证书有三条来源：ACME HTTP-01 自动签发与续期、手工上传、自签。通配符
//     只能用上传，因为 HTTP-01 无法验证 *.example.com——页面在 ACME 选项旁直接说明，
//     而不是等请求失败后才解释。
//   * 删除只删配置、软链接与面板管理的证书；网站根目录故意保留——删 vhost 不是删数据。
const state = ref(null);
const error = ref("");
const msg = ref("");
const busy = ref(false);
const form = ref({ name: "", domains: "", root: "", index: "", php_version: "" });

const siteFeat = computed(() => store.caps?.features?.site || null);
const siteWriteFeat = computed(() => store.caps?.features?.site_write || null);
const sslFeat = computed(() => store.caps?.features?.ssl || null);
const phpSwitchFeat = computed(() => store.caps?.features?.php_version_switch || null);
const phpVersions = computed(() => store.caps?.php_fpm_versions || []);
const available = computed(() => siteFeat.value?.state === "available" && siteWriteFeat.value?.state === "available");
const tlsAvailable = computed(() => ["available", "degraded"].includes(sslFeat.value?.state));
const phpAvailable = computed(() => phpSwitchFeat.value?.state === "available" && phpVersions.value.length > 0);
const feats = computed(() => [siteFeat.value, siteWriteFeat.value].filter(Boolean));
const rows = computed(() => state.value?.items || []);

const tlsOpen = ref(false);
const tlsTarget = ref(null);
const tlsForm = ref({ mode: "acme", redirect: true, cert_pem: "", key_pem: "" });
const hasWildcard = computed(() => (tlsTarget.value?.domains || []).some((d) => d.startsWith("*.")));
const acmeUsable = computed(() => !hasWildcard.value && ["available", "degraded"].includes(sslFeat.value?.state));

const phpOpen = ref(false);
const phpTarget = ref(null);
const phpForm = ref({ version: "" });

const editOpen = ref(false);
const editTarget = ref(null);
const editForm = ref({ domains: "", root: "", index: "" });

const rewritePresets = ref([]);
const rewriteOpen = ref(false);
const rewriteTarget = ref(null);
const rewriteForm = ref({ preset: "none" });

const configOpen = ref(false);
const configTarget = ref(null);
const configForm = ref({ path: "", content: "", original: "" });

const corsOpen = ref(false);
const corsTarget = ref(null);
const corsForm = ref({ origins: "", methods: [], headers: "", credentials: false, maxAge: 0 });
const corsMethodOptions = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

const proxyOpen = ref(false);
const proxyTarget = ref(null);
const proxyForm = ref({ mode: "single", target: "", websocket: false, method: "", upstreams: [] });
const maxProxyUpstreams = 10;
const proxyLBMethods = [
  { id: "", label: "轮询（nginx 默认）" },
  { id: "ip_hash", label: "ip_hash · 同一客户端 IP 固定同一后端" },
  { id: "least_conn", label: "least_conn · 转发给当前连接最少的后端" },
];
function blankUpstream() { return { target: "", weight: 1 }; }
// proxyOn is the one exclusion predicate: both proxy forms own location /.
function proxyOn(r) { return !!(r && (r.proxy_target || r.proxy_upstreams?.length)); }
function proxyFilled() {
  return proxyForm.value.mode === "single"
    ? !!proxyForm.value.target.trim()
    : proxyForm.value.upstreams.some(u => u.target.trim());
}

const redirectOpen = ref(false);
const redirectTarget = ref(null);
const redirectForm = ref({ target: "", code: 301, keep_path: true });

const hotlinkOpen = ref(false);
const hotlinkTarget = ref(null);
const hotlinkForm = ref({ enabled: false, allow_empty: true });

const authOpen = ref(false);
const authTarget = ref(null);
const authForm = ref({ username: "", password: "" });

const realOpen = ref(false);
const realTarget = ref(null);
const realForm = ref({ from: "", header: "X-Forwarded-For" });

const redirectPathsOpen = ref(false);
const redirectPathsTarget = ref(null);
const redirectPathRules = ref([]);
const maxRedirectPathRules = 10;

const errorPagesOpen = ref(false);
const errorPagesTarget = ref(null);
const errorPageRules = ref([]);
const maxErrorPageRules = 10;
const errorPageCodes = [400, 401, 403, 404, 405, 408, 500, 502, 503, 504];

const limitOpen = ref(false);
const limitTarget = ref(null);
// 四个字段全空表示清除限流，是始终允许的救援路径。rate 用文本而非数字，
// 因为它是 "10r/s" / "200r/m" 这类形状，由后端解析并规范化。
const limitForm = ref({ request_rate: "", burst: "", connections: "", status: "" });
const limitStatuses = [
  { value: "", label: "默认 503" },
  { value: "429", label: "429 Too Many Requests" },
  { value: "503", label: "503 Service Unavailable" },
];

// 分组 / 备注是面板侧元数据，不碰 nginx；搜索与分组过滤在已经 join 过 group/note
// 的列表上做即时过滤，不需要再打一次后端。
const metaOpen = ref(false);
const metaTarget = ref(null);
const metaForm = ref({ group: "", note: "" });
const search = ref("");
const groupFilter = ref("");

// 日志查看器是只读的：kind 与行数发给后端，路径由后端派生。logData 为 null
// 表示还没读；exists=false 是后端的真实回答（文件尚未产生），页面如实显示。
const logOpen = ref(false);
const logTarget = ref(null);
const logKind = ref("access");
const logLines = ref(100);
const logData = ref(null);
const logLoading = ref(false);

const groups = computed(() => {
  const set = new Set();
  for (const r of rows.value) if (r.group) set.add(r.group);
  return [...set].sort();
});

const filteredRows = computed(() => {
  const q = search.value.trim().toLowerCase();
  return rows.value.filter((r) => {
    if (groupFilter.value && r.group !== groupFilter.value) return false;
    if (!q) return true;
    const hay = [r.name, r.group, r.note, ...(r.domains || [])].join(" ").toLowerCase();
    return hay.includes(q);
  });
});

function openMeta(r) {
  metaTarget.value = r;
  metaForm.value = { group: r.group || "", note: r.note || "" };
  metaOpen.value = true;
}

async function saveMeta() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const body = { group: metaForm.value.group.trim(), note: metaForm.value.note.trim() };
    await api("/api/v1/sites/" + encodeURIComponent(metaTarget.value.name) + "/meta",
      { method: "PUT", body: JSON.stringify(body) });
    msg.value = (body.group || body.note)
      ? metaTarget.value.name + " 的分组 / 备注已保存（仅面板记录，不影响 nginx）"
      : metaTarget.value.name + " 的分组与备注已清除";
    metaOpen.value = false;
    await load();
  } catch (e) {
    // 400 分组/备注超长或含控制字符、404 站点不是面板管理的，都带后端原文。
    error.value = e.message;
  } finally { busy.value = false; }
}

// 目录列表是一个布尔开关：按钮直接提交取反后的值，后端渲染固定的 `autoindex`
// 指令并走 nginx -t → reload。开关状态以刷新后的列表为准，页面不自己记住。
async function toggleAutoIndex(r) {
  error.value = ""; msg.value = ""; busy.value = true;
  const want = !r.autoindex;
  try {
    await api("/api/v1/sites/" + encodeURIComponent(r.name) + "/autoindex",
      { method: "PUT", body: JSON.stringify({ enabled: want }) });
    msg.value = r.name + (want ? " 已开启目录列表（无默认文档的目录会列文件）" : " 已关闭目录列表");
    await load();
  } catch (e) { error.value = e.message; await load(); }
  finally { busy.value = false; }
}

// 强制 HTTPS 只在站点已启用证书时出现：没有证书时后端会拒绝并给出理由，
// 与其放一个点了必然报错的开关，不如按后端事实（r.tls.enabled）决定按钮可见性。
async function toggleForceHTTPS(r) {
  error.value = ""; msg.value = ""; busy.value = true;
  const want = !(r.tls && r.tls.redirect);
  try {
    await api("/api/v1/sites/" + encodeURIComponent(r.name) + "/force-https",
      { method: "PUT", body: JSON.stringify({ enabled: want }) });
    msg.value = r.name + (want ? " 已开启强制 HTTPS（HTTP 请求 301 到 HTTPS）" : " 已关闭强制 HTTPS");
    await load();
  } catch (e) { error.value = e.message; await load(); }
  finally { busy.value = false; }
}

// 日志查看：打开对话框即读一次，切换类型 / 行数或点刷新再读。后端负责路径派生、
// 所有权核对与尾部截断；页面只展示后端返回的事实，包括"文件尚不存在"。
function openLog(r) {
  logTarget.value = r;
  logKind.value = "access";
  logLines.value = 100;
  logData.value = null;
  logOpen.value = true;
  loadLog();
}

async function loadLog() {
  if (!logTarget.value) return;
  logLoading.value = true;
  error.value = "";
  try {
    logData.value = await api("/api/v1/sites/" + encodeURIComponent(logTarget.value.name) +
      "/logs?kind=" + logKind.value + "&lines=" + logLines.value);
  } catch (e) {
    logData.value = null;
    error.value = e.message;
  } finally { logLoading.value = false; }
}

function blankRedirectPathRule() {
  return { path: "", target: "", code: 301 };
}

function blankErrorPageRule() {
  return { code: 404, path: "" };
}

function parseDomains(text) {
  return String(text || "")
    .split(/[\s,，;；]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// 默认文档与域名不同：文件名区分大小写，也不该被转小写。
function parseIndex(text) {
  return String(text || "")
    .split(/[\s,，;；]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function load() {
  error.value = "";
  if (!available.value) return;
  try {
    const [sites, presets] = await Promise.all([
      api("/api/v1/sites"),
      api("/api/v1/sites/rewrite-presets"),
    ]);
    state.value = sites;
    rewritePresets.value = presets.items || [];
  }
  catch (e) { error.value = e.message; }
}

async function create() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const body = { name: form.value.name.trim(), domains: parseDomains(form.value.domains) };
    const root = form.value.root.trim();
    if (root) body.root = root;
    const index = parseIndex(form.value.index);
    if (index.length) body.index = index;
    if (form.value.php_version) body.php_version = form.value.php_version;
    const site = await api("/api/v1/sites", { method: "POST", body: JSON.stringify(body) });
    let php = "";
    if (site.php_version) {
      php = site.php_socket_state === "listening"
        ? "，已绑定 PHP " + site.php_version
        : "，已绑定 PHP " + site.php_version + "，但 " + phpSocketWords(site) + "，站点会返回 502";
    }
    msg.value = "已创建 " + site.name + "，nginx 已通过 nginx -t 并重载" + php + "。";
    form.value = { name: "", domains: "", root: "", index: "", php_version: "" };
    await load();
  } catch (e) {
    // 后端已经把 nginx -t 的输出带回来了（422 nginx_rejected），原样显示，
    // 不在前端把一段配置错误概括成"保存失败"。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

async function remove(name) {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    await api("/api/v1/sites/" + encodeURIComponent(name), { method: "DELETE" });
    msg.value = "已删除 " + name + " 的配置；网站根目录按设计保留。";
    await load();
  } catch (e) { error.value = e.message; await load(); }
  finally { busy.value = false; }
}

function openTLS(r) {
  error.value = ""; msg.value = "";
  tlsTarget.value = r;
  const wildcard = (r.domains || []).some((d) => d.startsWith("*."));
  tlsForm.value = {
    mode: wildcard ? "upload" : "acme",
    redirect: true,
    cert_pem: "",
    key_pem: "",
  };
  tlsOpen.value = true;
}

async function pickPEM(ev, key) {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    tlsForm.value[key] = await file.text();
  } catch (e) {
    error.value = "读取 " + file.name + " 失败：" + e.message;
  } finally {
    ev.target.value = "";
  }
}

async function saveTLS() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const body = { redirect: tlsForm.value.redirect };
    const name = encodeURIComponent(tlsTarget.value.name);
    let site;
    if (tlsForm.value.mode === "acme") {
      // 独立端点：签发要等 CA 做 HTTP-01 验证，不能和本地证书写入共用超时语义。
      site = await api("/api/v1/sites/" + name + "/acme",
        { method: "POST", body: JSON.stringify(body) });
      msg.value = site.name + " 已通过 ACME 签发并启用 HTTPS；面板会在到期前 30 天自动续期。";
    } else {
      body.mode = tlsForm.value.mode;
      if (tlsForm.value.mode === "upload") {
        body.cert_pem = tlsForm.value.cert_pem;
        body.key_pem = tlsForm.value.key_pem;
      }
      site = await api("/api/v1/sites/" + name + "/tls",
        { method: "POST", body: JSON.stringify(body) });
      msg.value = site.name + " 已启用 HTTPS" + (site.tls?.self_signed ? "（自签证书）" : "") +
        "；nginx 已通过 nginx -t 并重载。证书到期前请手工更换。";
    }
    tlsOpen.value = false;
    await load();
  } catch (e) {
    // 422 时后端带回的是 nginx -t 的原文，且配置/证书已回滚——原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

async function clearTLS(name) {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    await api("/api/v1/sites/" + encodeURIComponent(name) + "/tls", { method: "DELETE" });
    msg.value = name + " 已关闭 HTTPS，回到纯 HTTP；面板管理的证书与私钥已删除。";
    await load();
  } catch (e) { error.value = e.message; await load(); }
  finally { busy.value = false; }
}

function tlsLabel(r) {
  if (!r.tls?.enabled) return "HTTP";
  if (r.tls.acme) return "HTTPS · ACME";
  return r.tls.self_signed ? "HTTPS · 自签" : "HTTPS · 已上传";
}

function phpSocketOk(r) {
  return r.php_socket_state === "listening";
}

function phpSocketWords(r) {
  switch (r.php_socket_state) {
    case "idle": return "socket 存在但无人监听";
    case "absent": return "socket 不存在（fpm 未启动或未安装）";
    case "not_socket": return "同名文件不是 socket";
    case "unknown": return "无法读取内核 socket 表";
    default: return r.php_socket_state || "状态未知";
  }
}

function openPHP(r) {
  error.value = ""; msg.value = "";
  phpTarget.value = r;
  phpForm.value = { version: r.php_version || "" };
  phpOpen.value = true;
}

async function savePHP() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const site = await api("/api/v1/sites/" + encodeURIComponent(phpTarget.value.name) + "/php",
      { method: "PUT", body: JSON.stringify({ php_version: phpForm.value.version }) });
    if (site.php_version) {
      const warn = site.php_socket_state === "listening" ? "" :
        "；注意：" + phpSocketWords(site) + "，站点会返回 502，先启动对应版本的 php-fpm。";
      msg.value = site.name + " 已绑定 PHP " + site.php_version + "；nginx 已通过 nginx -t 并重载" + warn;
    } else {
      msg.value = site.name + " 已切回静态站点；.php 请求不再交给 php-fpm。";
    }
    phpOpen.value = false;
    await load();
  } catch (e) {
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function openEdit(r) {
  error.value = ""; msg.value = "";
  editTarget.value = r;
  editForm.value = {
    domains: (r.domains || []).join(" "),
    root: r.root || "",
    index: (r.index || []).join(" "),
  };
  editOpen.value = true;
}

async function saveEdit() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const body = { domains: parseDomains(editForm.value.domains) };
    const root = editForm.value.root.trim();
    if (root) body.root = root;
    const index = parseIndex(editForm.value.index);
    if (index.length) body.index = index;
    const site = await api("/api/v1/sites/" + encodeURIComponent(editTarget.value.name),
      { method: "PUT", body: JSON.stringify(body) });
    msg.value = site.name + " 的基础设置已更新；nginx 已通过 nginx -t 并重载。";
    editOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site / 422 invalid_tls / 422 nginx_rejected 都带后端原文；
    // 后端在返回前没有写入任何文件，页面只需要原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function rewritePreset(id) {
  return rewritePresets.value.find((p) => p.id === id) || null;
}

function rewriteLabel(r) {
  if (!r.rewrite || r.rewrite === "none") return "";
  return rewritePreset(r.rewrite)?.label || r.rewrite;
}

function openRewrite(r) {
  error.value = ""; msg.value = "";
  rewriteTarget.value = r;
  rewriteForm.value = { preset: r.rewrite || "none" };
  rewriteOpen.value = true;
}

async function saveRewrite() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const site = await api("/api/v1/sites/" + encodeURIComponent(rewriteTarget.value.name) + "/rewrite",
      { method: "PUT", body: JSON.stringify({ preset: rewriteForm.value.preset }) });
    msg.value = site.name + " 的伪静态已更新；nginx 已通过 nginx -t 并重载。";
    rewriteOpen.value = false;
    await load();
  } catch (e) {
    // 静态站点选择 PHP 模板会得到 400 invalid_site；后端没有写文件，原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function proxyLabel(r) {
  if (r.proxy_upstreams?.length) {
    return "负载均衡 · " + r.proxy_upstreams.length + " 个后端" +
      (r.proxy_lb_method ? " · " + r.proxy_lb_method : "") +
      (r.proxy_websocket ? " · WebSocket" : "");
  }
  if (!r.proxy_target) return "";
  return "代理 · " + r.proxy_target + (r.proxy_websocket ? " · WebSocket" : "");
}

function openProxy(r) {
  error.value = ""; msg.value = "";
  proxyTarget.value = r;
  proxyForm.value = {
    mode: r.proxy_upstreams?.length ? "multi" : "single",
    target: r.proxy_target || "",
    websocket: !!r.proxy_websocket,
    method: r.proxy_lb_method || "",
    upstreams: r.proxy_upstreams?.length
      ? r.proxy_upstreams.map(u => ({ target: u.target, weight: u.weight || 1 }))
      : [blankUpstream()],
  };
  proxyOpen.value = true;
}

function addUpstream() {
  if (proxyForm.value.upstreams.length < maxProxyUpstreams) proxyForm.value.upstreams.push(blankUpstream());
}
function removeUpstream(i) { proxyForm.value.upstreams.splice(i, 1); }

async function saveProxy() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const name = encodeURIComponent(proxyTarget.value.name);
    if (proxyForm.value.mode === "multi") {
      // Empty rows are dropped; an entirely empty table is the clear path.
      const upstreams = proxyForm.value.upstreams
        .filter(u => u.target.trim())
        .map(u => ({ target: u.target.trim(), weight: Number(u.weight) || 1 }));
      const site = await api("/api/v1/sites/" + name + "/proxy-upstreams",
        { method: "PUT", body: JSON.stringify({ upstreams, method: proxyForm.value.method, websocket: proxyForm.value.websocket }) });
      if (site.proxy_upstreams?.length) {
        msg.value = site.name + " 已启用负载均衡：" + site.proxy_upstreams.length + " 个后端" +
          (site.proxy_lb_method ? "（" + site.proxy_lb_method + "）" : "（轮询）") +
          (site.proxy_websocket ? "，含 WebSocket 升级" : "") +
          "；vhost 与 upstream 表在同一次事务里通过 nginx -t 并重载。";
      } else {
        msg.value = site.name + " 已清除负载均衡，location / 回到默认静态查找；nginx 已通过 nginx -t 并重载。";
      }
    } else {
      const target = proxyForm.value.target.trim();
      const site = await api("/api/v1/sites/" + name + "/proxy",
        { method: "PUT", body: JSON.stringify({ target, websocket: proxyForm.value.websocket }) });
      if (site.proxy_target) {
        msg.value = site.name + " 已反向代理到 " + site.proxy_target +
          (site.proxy_websocket ? "（含 WebSocket 升级）" : "") +
          "；nginx 已通过 nginx -t 并重载。";
      } else {
        msg.value = site.name + " 已清除反向代理，location / 回到默认静态查找；nginx 已通过 nginx -t 并重载。";
      }
    }
    proxyOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（URL / 权重 / 算法不合法、与伪静态冲突、或本机没有 http 级通配
    // include）与 422 nginx_rejected 都带后端原文；后端在返回前已回滚，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function redirectLabel(r) {
  if (!r.redirect_target) return "";
  return "跳转 " + (r.redirect_code || 301) + " · " + r.redirect_target +
    (r.redirect_keep_path ? " · 保留路径" : "");
}

function openRedirect(r) {
  error.value = ""; msg.value = "";
  redirectTarget.value = r;
  redirectForm.value = {
    target: r.redirect_target || "",
    code: r.redirect_code || 301,
    keep_path: r.redirect_target ? !!r.redirect_keep_path : true,
  };
  redirectOpen.value = true;
}

async function saveRedirect() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const target = redirectForm.value.target.trim();
    const code = target ? redirectForm.value.code : 0;
    const keepPath = target ? redirectForm.value.keep_path : false;
    const site = await api("/api/v1/sites/" + encodeURIComponent(redirectTarget.value.name) + "/redirect",
      { method: "PUT", body: JSON.stringify({ target, code, keep_path: keepPath }) });
    if (site.redirect_target) {
      msg.value = site.name + " 已整站跳转到 " + site.redirect_target +
        "（" + site.redirect_code + (site.redirect_keep_path ? "，保留路径" : "") + "）" +
        "；nginx 已通过 nginx -t 并重载。";
    } else {
      msg.value = site.name + " 已清除整站跳转，location / 回到默认静态查找；nginx 已通过 nginx -t 并重载。";
    }
    redirectOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（URL / 状态码不合法或与伪静态、代理冲突）与 422 nginx_rejected
    // 都带后端原文；后端返回前没有写入任何文件，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function hotlinkLabel(r) {
  if (!r.hotlink) return "";
  return "防盗链 · " + (r.hotlink_allow_empty ? "允许直接访问" : "仅本站来源");
}

function openHotlink(r) {
  error.value = ""; msg.value = "";
  hotlinkTarget.value = r;
  hotlinkForm.value = {
    enabled: !!r.hotlink,
    allow_empty: r.hotlink ? !!r.hotlink_allow_empty : true,
  };
  hotlinkOpen.value = true;
}

async function saveHotlink() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const site = await api("/api/v1/sites/" + encodeURIComponent(hotlinkTarget.value.name) + "/hotlink",
      { method: "PUT", body: JSON.stringify({ enabled: hotlinkForm.value.enabled, allow_empty: hotlinkForm.value.allow_empty }) });
    if (site.hotlink) {
      msg.value = site.name + " 已启用防盗链（" +
        (site.hotlink_allow_empty ? "放行无 Referer 请求" : "只允许本站来源") +
        "）；nginx 已通过 nginx -t 并重载。";
    } else {
      msg.value = site.name + " 已关闭防盗链，静态资源回到默认处理；nginx 已通过 nginx -t 并重载。";
    }
    hotlinkOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（与代理 / 整站跳转冲突）与 422 nginx_rejected 都带后端原文；
    // 后端返回前没有写入任何文件，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function openAuth(r) {
  error.value = ""; msg.value = "";
  authTarget.value = r;
  // 口令永远不会从后端读回：已启用的站点只回填用户名，保存时必须重新输入口令。
  authForm.value = { username: r.auth_user || "", password: "" };
  authOpen.value = true;
}

async function saveAuth() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const username = authForm.value.username.trim();
    const password = authForm.value.password;
    if (!!username !== !!password) {
      error.value = "用户名与口令必须同时给出；两项都留空表示关闭访问密码。";
      return;
    }
    const site = await api("/api/v1/sites/" + encodeURIComponent(authTarget.value.name) + "/auth",
      { method: "PUT", body: JSON.stringify({ username, password }) });
    if (site.auth_user) {
      msg.value = site.name + " 已启用访问密码（用户名 " + site.auth_user +
        "）；口令只以 {SHA} 形式写入面板的 0600 文件，vhost 已通过 nginx -t（vhost 未变时不会重载）。";
    } else {
      msg.value = site.name + " 已关闭访问密码，口令文件已删除；nginx 已通过 nginx -t 并重载。";
    }
    authForm.value = { username: "", password: "" };
    authOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（用户名 / 口令不合法）与 422 nginx_rejected 都带后端原文；
    // 后端返回前配置与口令文件已一起恢复，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

async function openConfig(r) {
  error.value = ""; msg.value = "";
  configTarget.value = r;
  busy.value = true;
  try {
    const cfg = await api("/api/v1/sites/" + encodeURIComponent(r.name) + "/config");
    configForm.value = { path: cfg.path, content: cfg.content, original: cfg.content };
    configOpen.value = true;
  } catch (e) {
    // 403 capability / 404 not_found 都带后端原文；不摆一个空编辑器。
    error.value = e.message;
  } finally { busy.value = false; }
}

async function saveConfig() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const cfg = await api("/api/v1/sites/" + encodeURIComponent(configTarget.value.name) + "/config",
      { method: "PUT", body: JSON.stringify({ content: configForm.value.content }) });
    configForm.value.original = cfg.content;
    msg.value = configTarget.value.name + " 的配置已保存：nginx 已通过 nginx -t 并重载。" +
      "注意：后续任何面板功能写入都会按标记重新生成整份配置，手工添加的指令会被覆盖。";
    configOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（标记行被删改/超长）与 422 nginx_rejected 都带后端原文；
    // 后端在返回前已恢复原字节，编辑器保留当前文本供修改。
    error.value = e.message;
  } finally { busy.value = false; }
}

function corsLabel(r) {
  if (!r.cors?.origins?.length) return "";
  const o = r.cors.origins[0] === "*" ? "任意来源" : r.cors.origins.length + " 个来源";
  return "CORS · " + o + (r.cors.credentials ? " · 凭据" : "");
}

function openCors(r) {
  error.value = ""; msg.value = "";
  corsTarget.value = r;
  corsForm.value = {
    origins: (r.cors?.origins || []).join("\n"),
    methods: r.cors?.methods ? [...r.cors.methods] : [],
    headers: (r.cors?.headers || []).join(", "),
    credentials: !!r.cors?.credentials,
    maxAge: r.cors?.max_age || 0,
  };
  corsOpen.value = true;
}

async function saveCors() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const origins = parseDomains(corsForm.value.origins);
    const headers = corsForm.value.headers.split(",").map(h => h.trim()).filter(Boolean);
    const site = await api("/api/v1/sites/" + encodeURIComponent(corsTarget.value.name) + "/cors",
      { method: "PUT", body: JSON.stringify({
        origins, methods: corsForm.value.methods, headers,
        credentials: corsForm.value.credentials, max_age: Number(corsForm.value.maxAge) || 0,
      }) });
    if (site.cors?.origins?.length) {
      msg.value = site.name + " 已启用 CORS：" +
        (site.cors.origins[0] === "*" ? "允许任意来源" : "允许 " + site.cors.origins.length + " 个来源") +
        "；OPTIONS 预检由本机直接回 204，nginx 已通过 nginx -t 并重载。";
    } else {
      msg.value = site.name + " 已清除 CORS 策略，跨域响应头与 OPTIONS 短路一并移除。";
    }
    corsOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（来源/方法/请求头/缓存时间不合法、* 与凭据混用）与
    // 422 nginx_rejected 都带后端原文；后端在返回前没有留下任何写入。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function openRealIP(r) {
  error.value = ""; msg.value = "";
  realTarget.value = r;
  realForm.value = {
    from: (r.real_ip_from || []).join("\n"),
    header: r.real_ip_header || "X-Forwarded-For",
  };
  realOpen.value = true;
}

async function saveRealIP() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const from = parseDomains(realForm.value.from);
    if (!from.length && !realTarget.value.real_ip_from?.length) {
      error.value = "启用真实 IP 解析至少要给出一个可信代理地址或网段；列表留空表示关闭，仅对已启用的站点有效。";
      return;
    }
    const header = from.length ? realForm.value.header : "";
    const site = await api("/api/v1/sites/" + encodeURIComponent(realTarget.value.name) + "/realip",
      { method: "PUT", body: JSON.stringify({ from, header }) });
    if (site.real_ip_from?.length) {
      msg.value = site.name + " 已启用真实 IP 解析：信任 " + site.real_ip_from.length + " 个代理来源，读取 " +
        site.real_ip_header + "；不在列表里的客户端不能通过伪造请求头改变日志来源。";
    } else {
      msg.value = site.name + " 已关闭真实 IP 解析，站点恢复直接使用对端地址。";
    }
    realForm.value = { from: "", header: "X-Forwarded-For" };
    realOpen.value = false;
    await load();
  } catch (e) {
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function redirectPathsWords(r) {
  const rules = r.redirect_paths || [];
  return rules.slice(0, 3).map((p) => p.path + "→" + p.code).join("、") +
    (rules.length > 3 ? "…" : "");
}

function openRedirectPaths(r) {
  error.value = ""; msg.value = "";
  redirectPathsTarget.value = r;
  const rules = (r.redirect_paths || []).map((p) => ({
    path: p.path || "",
    target: p.target || "",
    code: p.code === 302 ? 302 : 301,
  }));
  redirectPathRules.value = rules.length ? rules : [blankRedirectPathRule()];
  redirectPathsOpen.value = true;
}

function addRedirectPath() {
  error.value = ""; msg.value = "";
  if (redirectPathRules.value.length >= maxRedirectPathRules) {
    error.value = "按路径跳转最多 " + maxRedirectPathRules + " 条。";
    return;
  }
  redirectPathRules.value.push(blankRedirectPathRule());
}

function removeRedirectPath(index) {
  redirectPathRules.value.splice(index, 1);
}

function normalizedRedirectPath(path) {
  const trimmed = String(path || "").trim();
  return trimmed.replace(/\/+$/, "") || "/";
}

async function saveRedirectPaths() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const rules = redirectPathRules.value
      .map((r) => ({
        path: String(r.path || "").trim(),
        target: String(r.target || "").trim(),
        code: Number(r.code),
      }))
      .filter((r) => r.path || r.target)
      .map((r) => ({ ...r, path: normalizedRedirectPath(r.path) }));

    if (rules.length > maxRedirectPathRules) {
      error.value = "按路径跳转最多 " + maxRedirectPathRules + " 条。";
      return;
    }

    const seen = new Set();
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const row = i + 1;
      if (!rule.path || !rule.target) {
        error.value = "第 " + row + " 条的路径与跳转目标必须同时填写；两者都留空表示删除这一行。";
        return;
      }
      if (rule.path === "/") {
        error.value = "第 " + row + " 条路径不能是站点根路径 /；它已经由整站跳转或 location / 接管。";
        return;
      }
      if (!/^\/[A-Za-z0-9._~/-]{0,127}$/.test(rule.path)) {
        error.value = "第 " + row + " 条路径只能以 / 开头，只允许字母、数字与 . _ ~ / -，且最长 128 个字符。";
        return;
      }
      if (rule.path.includes("..") || rule.path.startsWith("/.well-known/acme-challenge")) {
        error.value = "第 " + row + " 条路径不能包含 ..，也不能遮蔽 ACME 校验路径。";
        return;
      }
      if (seen.has(rule.path)) {
        error.value = "第 " + row + " 条路径 " + rule.path + " 与前面的路径重复。";
        return;
      }
      seen.add(rule.path);
      if (rule.code !== 301 && rule.code !== 302) {
        error.value = "第 " + row + " 条跳转状态码只能是 301 或 302。";
        return;
      }
    }

    const site = await api("/api/v1/sites/" + encodeURIComponent(redirectPathsTarget.value.name) + "/redirect-paths",
      { method: "PUT", body: JSON.stringify({ rules }) });
    msg.value = site.name + " 的按路径跳转表已" +
      (site.redirect_paths?.length ? "更新（" + site.redirect_paths.length + " 条精确匹配，保留查询串）" : "清除") +
      "；nginx 已通过 nginx -t 并重载。";
    redirectPathsOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（路径、目标或状态码不合法）与 422 nginx_rejected 都带后端原文；
    // 后端在返回前没有写入任何文件，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function errorPagesWords(r) {
  const rules = r.error_pages || [];
  return rules.slice(0, 4).map((p) => p.code + "→" + p.path).join("、") +
    (rules.length > 4 ? "…" : "");
}

function openErrorPages(r) {
  error.value = ""; msg.value = "";
  errorPagesTarget.value = r;
  const rules = (r.error_pages || []).map((p) => ({
    code: errorPageCodes.includes(p.code) ? p.code : 404,
    path: p.path || "",
  }));
  errorPageRules.value = rules.length ? rules : [blankErrorPageRule()];
  errorPagesOpen.value = true;
}

function addErrorPage() {
  error.value = ""; msg.value = "";
  if (errorPageRules.value.length >= maxErrorPageRules) {
    error.value = "自定义错误页最多 " + maxErrorPageRules + " 条。";
    return;
  }
  errorPageRules.value.push(blankErrorPageRule());
}

function removeErrorPage(index) {
  errorPageRules.value.splice(index, 1);
}

async function saveErrorPages() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const rules = errorPageRules.value
      .map((r) => ({ code: Number(r.code), path: String(r.path || "").trim() }))
      .filter((r) => r.path);

    if (rules.length > maxErrorPageRules) {
      error.value = "自定义错误页最多 " + maxErrorPageRules + " 条。";
      return;
    }

    const seen = new Set();
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const row = i + 1;
      if (!errorPageCodes.includes(rule.code)) {
        error.value = "第 " + row + " 条状态码不在支持列表（400/401/403/404/405/408/500/502/503/504）。";
        return;
      }
      if (seen.has(rule.code)) {
        error.value = "第 " + row + " 条状态码 " + rule.code + " 与前面的重复。";
        return;
      }
      seen.add(rule.code);
      if (!/^\/[A-Za-z0-9._~/-]{1,127}$/.test(rule.path)) {
        error.value = "第 " + row + " 条路径只能以 / 开头，只允许字母、数字与 . _ ~ / -，且最长 128 个字符。";
        return;
      }
      if (rule.path.includes("..") || rule.path.startsWith("/.well-known/acme-challenge")) {
        error.value = "第 " + row + " 条路径不能包含 ..，也不能遮蔽 ACME 校验路径。";
        return;
      }
    }

    const site = await api("/api/v1/sites/" + encodeURIComponent(errorPagesTarget.value.name) + "/error-pages",
      { method: "PUT", body: JSON.stringify({ rules }) });
    msg.value = site.name + " 的自定义错误页已" +
      (site.error_pages?.length ? "更新（" + site.error_pages.length + " 条 error_page 指令）" : "清除") +
      "；nginx 已通过 nginx -t 并重载。";
    errorPagesOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（状态码或路径不合法）与 422 nginx_rejected 都带后端原文；
    // 后端在返回前已恢复原字节，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

function limitLabel(r) {
  const l = r.limits;
  if (!l) return "";
  const parts = [];
  if (l.request_rate) parts.push(l.request_rate + (l.burst ? " (burst " + l.burst + ")" : ""));
  if (l.connections) parts.push("并发 " + l.connections);
  parts.push("超限 " + (l.status || 503));
  return parts.join(" · ");
}

function openLimit(r) {
  error.value = ""; msg.value = "";
  limitTarget.value = r;
  const l = r.limits || {};
  limitForm.value = {
    request_rate: l.request_rate || "",
    burst: l.burst ? String(l.burst) : "",
    connections: l.connections ? String(l.connections) : "",
    status: l.status ? String(l.status) : "",
  };
  limitOpen.value = true;
}

// 四个字段留空即清除限流；这里只做前端能判断的形状检查，真正的速率解析、
// 数值上界与"rate 之外的字段必须配合 rate"规则都由后端权威裁定，页面不复制一套。
async function saveLimit() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const rate = limitForm.value.request_rate.trim();
    const body = {};
    if (rate) body.request_rate = rate;
    const burst = limitForm.value.burst.trim();
    const conns = limitForm.value.connections.trim();
    const status = limitForm.value.status.trim();
    if (burst) {
      if (!rate) {
        error.value = "突发值只在设置了请求速率上限时才有意义；请先填写速率，或把突发留空。";
        busy.value = false;
        return;
      }
      body.burst = Number(burst);
    }
    if (conns) body.connections = Number(conns);
    if (status) body.status = Number(status);
    // 四项全空时 body 就是 {}，即后端文档里的清除限流救援路径。
    const site = await api("/api/v1/sites/" + encodeURIComponent(limitTarget.value.name) + "/traffic-limit",
      { method: "PUT", body: JSON.stringify(body) });
    if (site.limits) {
      msg.value = site.name + " 已启用流量限制（" + limitLabel(site) +
        "）；vhost 与 http 级 zone 表在同一次 nginx -t 通过后重载。";
    } else {
      msg.value = site.name + " 已清除流量限制；若这是本机最后一个限流站点，面板会一并删除它生成的 zone 表文件。";
    }
    limitOpen.value = false;
    await load();
  } catch (e) {
    // 400 invalid_site（速率/数值不合法，或本机 nginx.conf 没有 http 级通配 include）
    // 与 422 nginx_rejected 都带后端原文；后端返回前 vhost 与 zone 表已一起恢复，页面原样显示。
    error.value = e.message;
    await load();
  } finally { busy.value = false; }
}

onMounted(load);
</script>
<template>
  <div class="mp-card">
    <h3>网站</h3>
    <p class="mp-note">
      管理面板自己创建的站点；可以在创建时或之后绑定一个本机探测到的 PHP fpm 版本，留空则是
      <b>静态站点</b>。站点的域名、根目录、默认文档、伪静态模板与反向代理可随时编辑。每一次创建、
      编辑、删除、PHP 切换、伪静态、代理或证书变更都是"先测试后生效"：写配置 →
      <code class="mp-code">nginx -t</code> → 只有通过才 reload；任何一步失败都会恢复上一份配置与证书。
      只列出面板自己写出的 vhost（文件内带标记），手工写的配置不会被列出来，也不会被删除。
    </p>

    <template v-if="!available">
      <el-alert v-for="(f, i) in feats" :key="i" type="warning" :closable="false" style="margin-bottom:8px"
        :title="'当前不可用：' + (f.reason || '后端未给出理由（缺陷，请报告）')">
        <div v-if="f.fix_action" class="mp-muted mp-tiny">修复路径：{{ f.fix_action }}<span v-if="f.verify"> · 复核：{{ f.verify }}</span></div>
      </el-alert>
      <div class="mp-hint">
        站点写入需要本机安装 nginx、面板以 root 运行，并且 <code class="mp-code">/etc/nginx</code>
        下存在 <code class="mp-code">sites-available/sites-enabled</code> 或 <code class="mp-code">conf.d</code>。
        能力位图（本机能力页）里是同一句理由——这两处不会各说一套。
      </div>
    </template>

    <template v-else>
      <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-bottom:8px" />
      <el-alert v-if="msg" :title="msg" type="success" :closable="false" style="margin-bottom:8px" />
      <el-alert v-if="sslFeat && !tlsAvailable" type="warning" :closable="false" style="margin-bottom:8px"
        :title="'站点 HTTPS 不可用：' + (sslFeat.reason || '后端未给出理由（缺陷，请报告）')" />
      <el-alert v-else-if="sslFeat && sslFeat.state === 'degraded'" type="info" :closable="false" style="margin-bottom:8px"
        :title="sslFeat.reason">
        <div v-if="sslFeat.fix_action" class="mp-muted mp-tiny">操作路径：{{ sslFeat.fix_action }}<span v-if="sslFeat.verify"> · 复核：{{ sslFeat.verify }}</span></div>
      </el-alert>
      <el-alert v-if="phpSwitchFeat && !phpAvailable" type="info" :closable="false" style="margin-bottom:8px"
        :title="'站点 PHP 版本绑定不可用：' + (phpSwitchFeat.reason || '后端未给出理由（缺陷，请报告）')">
        <div v-if="phpSwitchFeat.fix_action" class="mp-muted mp-tiny">补齐：{{ phpSwitchFeat.fix_action }}<span v-if="phpSwitchFeat.verify"> · 复核：{{ phpSwitchFeat.verify }}</span></div>
      </el-alert>

      <el-form label-position="top" @submit.prevent="create">
        <div class="mp-row" style="align-items:flex-start;gap:12px;flex-wrap:wrap">
          <el-form-item label="站点名（2-32 位小写字母/数字/连字符）" style="min-width:220px">
            <el-input v-model="form.name" placeholder="blog" maxlength="32" />
          </el-form-item>
          <el-form-item label="域名（空格或逗号分隔，支持 *.example.com）" style="min-width:320px;flex:1">
            <el-input v-model="form.domains" placeholder="blog.example.com www.blog.example.com" />
          </el-form-item>
        </div>
        <el-form-item label="网站根目录（可省略，默认 <站点根目录>/<站点名>）">
          <el-input v-model="form.root" placeholder="留空即可" style="max-width:420px" />
        </el-form-item>
        <el-form-item label="默认文档（可省略，空格分隔；留空用内置列表）">
          <el-input v-model="form.index" placeholder="index.html index.htm" style="max-width:420px" />
          <div class="mp-hint" style="margin-top:4px">
            绑定 PHP 时内置列表以 index.php 优先；静态站点不允许把 .php 文件写成默认文档，
            否则 nginx 会把源码当文本返回。
          </div>
        </el-form-item>
        <el-form-item label="PHP 版本（可省略，留空为纯静态）">
          <el-select v-model="form.php_version" placeholder="纯静态" style="width:260px" :disabled="!phpAvailable">
            <el-option label="纯静态（不执行 PHP）" value="" />
            <el-option v-for="v in phpVersions" :key="v" :label="'PHP ' + v + '（fpm）'" :value="v" />
          </el-select>
          <div v-if="!phpAvailable" class="mp-hint" style="margin-top:4px">
            {{ phpSwitchFeat?.reason || '本机没有可绑定的 php-fpm 版本。' }}
          </div>
        </el-form-item>
        <el-button type="primary" size="small" :loading="busy" @click="create">创建站点</el-button>
      </el-form>

      <div class="mp-row" style="margin:14px 0 10px;align-items:center;gap:10px;flex-wrap:wrap">
        <el-button size="small" :loading="busy" @click="load">刷新</el-button>
        <el-input v-model="search" size="small" placeholder="搜索站点名 / 域名 / 分组 / 备注"
          clearable style="max-width:260px" />
        <el-select v-model="groupFilter" size="small" placeholder="全部分组" clearable style="max-width:180px">
          <el-option v-for="g in groups" :key="g" :label="g" :value="g" />
        </el-select>
        <span class="mp-muted mp-tiny">
          共 {{ rows.length }} 个由面板管理的站点<span v-if="filteredRows.length !== rows.length">
            · 过滤后 {{ filteredRows.length }} 个</span>
        </span>
      </div>

      <table>
        <thead>
          <tr><th>站点</th><th>域名</th><th>根目录</th><th>状态</th><th>PHP</th><th>HTTPS</th><th>创建时间</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="r in filteredRows" :key="r.name">
            <td>
              <b>{{ r.name }}</b>
              <span v-if="r.group" class="mp-tag" :title="'分组：' + r.group">{{ r.group }}</span>
              <div v-if="r.note" class="mp-muted mp-tiny mp-note-cell" :title="r.note">{{ r.note }}</div>
              <div class="mp-muted mp-tiny"><code class="mp-code">{{ r.config_path }}</code></div>
            </td>
            <td><span class="mp-clip" :title="r.domains.join(' ')">{{ r.domains.join(" · ") }}</span></td>
            <td>
              <code class="mp-code">{{ r.root }}</code>
              <div v-if="r.index?.length" class="mp-muted mp-tiny">index {{ r.index.join(" ") }}</div>
              <div v-if="rewriteLabel(r)" class="mp-muted mp-tiny">伪静态 · {{ rewriteLabel(r) }}</div>
              <div v-if="r.proxy_target" class="mp-muted mp-tiny">
                代理 · <code class="mp-code">{{ r.proxy_target }}</code>
                <span v-if="r.proxy_websocket"> · WebSocket</span>
              </div>
              <div v-if="r.proxy_upstreams?.length" class="mp-muted mp-tiny">
                负载均衡 {{ r.proxy_upstreams.length }} 个后端 · {{ r.proxy_lb_method || "轮询" }}
                <span v-if="r.proxy_websocket"> · WebSocket</span>
                <div><code class="mp-code">{{ r.proxy_upstreams.map(u => u.target + (u.weight > 1 ? " ×" + u.weight : "")).join(" ") }}</code></div>
              </div>
              <div v-if="r.redirect_target" class="mp-muted mp-tiny">
                跳转 {{ r.redirect_code || 301 }} · <code class="mp-code">{{ r.redirect_target }}</code>
                <span v-if="r.redirect_keep_path"> · 保留路径</span>
              </div>
              <div v-if="r.hotlink" class="mp-muted mp-tiny">
                防盗链 · {{ r.hotlink_allow_empty ? "允许直接访问" : "仅本站来源" }}
              </div>
              <div v-if="r.auth_user" class="mp-muted mp-tiny">
                访问密码 · 用户名 <code class="mp-code">{{ r.auth_user }}</code>
              </div>
              <div v-if="r.real_ip_from?.length" class="mp-muted mp-tiny">
                真实 IP · {{ r.real_ip_header }} · {{ r.real_ip_from.join("、") }}
              </div>
              <div v-if="r.redirect_paths?.length" class="mp-muted mp-tiny">
                路径跳转 {{ r.redirect_paths.length }} 条 ·
                <code class="mp-code">{{ redirectPathsWords(r) }}</code>
              </div>
              <div v-if="r.error_pages?.length" class="mp-muted mp-tiny">
                错误页 {{ r.error_pages.length }} 条 ·
                <code class="mp-code">{{ errorPagesWords(r) }}</code>
              </div>
              <div v-if="r.limits" class="mp-muted mp-tiny">流量限制 · {{ limitLabel(r) }}</div>
              <div v-if="r.cors?.origins?.length" class="mp-muted mp-tiny">
                {{ corsLabel(r) }} · {{ (r.cors.methods || ["GET","HEAD","POST"]).join("/") }}
                <div><code class="mp-code">{{ r.cors.origins.join(" ") }}</code></div>
              </div>
            </td>
            <td>
              <span class="mp-tag on" v-if="r.enabled">已启用</span>
              <span class="mp-tag flat" v-else>未启用</span>
            </td>
            <td>
              <span v-if="r.php_version" class="mp-tag" :class="phpSocketOk(r) ? 'on' : 'partial'">
                PHP {{ r.php_version }}
              </span>
              <span v-else class="mp-tag flat">静态</span>
              <div v-if="r.php_version && !phpSocketOk(r)" class="mp-muted mp-tiny">
                {{ phpSocketWords(r) }} · 站点会 502
              </div>
              <div v-else-if="r.php_version" class="mp-muted mp-tiny">
                <code class="mp-code">{{ r.php_socket }}</code>
              </div>
            </td>
            <td>
              <span class="mp-tag" :class="r.tls?.enabled ? 'on' : 'flat'">{{ tlsLabel(r) }}</span>
              <div v-if="r.tls?.enabled && r.tls.not_after" class="mp-muted mp-tiny">
                到期 {{ r.tls.not_after }}<span v-if="r.tls.redirect"> · 80→443</span>
                <span v-if="r.tls.acme"> · 自动续期</span>
              </div>
            </td>
            <td class="mp-muted mp-tiny">{{ r.created_at }}</td>
            <td style="width:1260px;white-space:nowrap">
              <el-button size="small" text type="primary" @click="openEdit(r)">编辑</el-button>
              <el-button size="small" text type="primary" @click="openRewrite(r)">伪静态</el-button>
              <el-button size="small" text type="primary" @click="openProxy(r)">
                {{ proxyOn(r) ? "代理" : "反代" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openRedirect(r)">
                {{ r.redirect_target ? "跳转" : "整站跳转" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openRedirectPaths(r)">路径跳转</el-button>
              <el-button size="small" text type="primary" @click="openErrorPages(r)">
                {{ r.error_pages?.length ? "错误页" : "自定义错误页" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openHotlink(r)">
                {{ r.hotlink ? "防盗链" : "防盗" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openAuth(r)">
                {{ r.auth_user ? "访问密码" : "加密码" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openRealIP(r)">真实 IP</el-button>
              <el-button size="small" text type="primary" @click="openCors(r)">
                {{ r.cors?.origins?.length ? "CORS" : "跨域" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openConfig(r)">配置</el-button>
              <el-button size="small" text type="primary" @click="openLimit(r)">
                {{ r.limits ? "限流" : "流量限制" }}
              </el-button>
              <el-button size="small" text type="primary" @click="openMeta(r)">
                {{ r.group || r.note ? "分组备注" : "分组/备注" }}
              </el-button>
              <el-button size="small" text type="primary" @click="toggleAutoIndex(r)">
                {{ r.autoindex ? "关目录列表" : "目录列表" }}
              </el-button>
              <el-popconfirm v-if="r.tls?.enabled"
                :title="r.tls.redirect ? '关闭强制 HTTPS？80 端口将恢复直接提供服务，不再 301 到 443。' : '开启强制 HTTPS？所有 HTTP 请求将 301 跳转到 HTTPS（ACME 续期路径由后端豁免）。'"
                confirm-button-text="确认" cancel-button-text="取消" width="300" @confirm="toggleForceHTTPS(r)">
                <template #reference>
                  <el-button size="small" text type="primary">
                    {{ r.tls.redirect ? "关强制HTTPS" : "强制HTTPS" }}
                  </el-button>
                </template>
              </el-popconfirm>
              <el-button size="small" text type="primary" @click="openLog(r)">日志</el-button>
              <el-button size="small" text type="primary" :disabled="!phpAvailable && !r.php_version" @click="openPHP(r)">
                PHP
              </el-button>
              <el-button size="small" text type="primary" :disabled="!tlsAvailable" @click="openTLS(r)">
                {{ r.tls?.enabled ? "更换证书" : "启用 HTTPS" }}
              </el-button>
              <el-popconfirm v-if="r.tls?.enabled" title="关闭 HTTPS 并删除面板管理的证书与私钥？站点仍以 HTTP 提供服务。"
                confirm-button-text="确认关闭" cancel-button-text="取消" confirm-button-type="danger" width="300" @confirm="clearTLS(r.name)">
                <template #reference>
                  <el-button size="small" text type="warning">关闭</el-button>
                </template>
              </el-popconfirm>
              <el-popconfirm title="删除这个站点的配置？网站根目录会保留。" confirm-button-text="确认删除"
                cancel-button-text="取消" confirm-button-type="danger" width="280" @confirm="remove(r.name)">
                <template #reference>
                  <el-button size="small" text type="danger">删除</el-button>
                </template>
              </el-popconfirm>
            </td>
          </tr>
          <tr v-if="!rows.length"><td colspan="8" class="mp-muted">还没有由面板创建的站点。</td></tr>
        </tbody>
      </table>

      <el-dialog v-model="editOpen" :title="'编辑 · ' + (editTarget?.name || '')" width="min(620px, 94vw)">
        <el-alert v-if="editTarget?.tls?.enabled" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用 HTTPS：修改域名时后端会先用现有证书校验新域名集合。证书覆盖不了新名字会返回 422 且不写文件；需要先关闭 HTTPS，编辑后重新签发或上传。" />
        <el-form label-position="top" @submit.prevent="saveEdit">
          <el-form-item label="域名（空格或逗号分隔，支持 *.example.com）">
            <el-input v-model="editForm.domains" placeholder="example.com www.example.com" />
          </el-form-item>
          <el-form-item label="网站根目录（必须位于站点根目录之下）">
            <el-input v-model="editForm.root" placeholder="/www/wwwroot/example" />
          </el-form-item>
          <el-form-item label="默认文档（留空恢复内置列表）">
            <el-input v-model="editForm.index" placeholder="index.html index.htm" />
            <div class="mp-hint" style="margin-top:6px">
              按输入顺序写入 vhost，最多 10 项，每项只能是文件名。站点未绑定 PHP 时不能写
              .php / .phtml / .phar 项。修改根目录不会移动或删除旧目录中的任何文件。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="editOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveEdit">保存</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="rewriteOpen" :title="'伪静态 · ' + (rewriteTarget?.name || '')" width="min(560px, 94vw)">
        <el-alert v-if="proxyOn(rewriteTarget)" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用反向代理：两者都占用 location /。除“默认”以外的模板会被后端拒绝；请先在“代理”对话框里清空上游 URL。" />
        <el-alert v-if="rewriteTarget?.redirect_target" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点正在整站跳转：两者都占用 location /。除“默认”以外的模板会被后端拒绝；请先在“整站跳转”对话框里清空跳转目标。" />
        <el-alert v-if="rewriteTarget && !rewriteTarget.php_version" type="info" :closable="false" style="margin-bottom:10px"
          title="当前是静态站点：需要 PHP 的模板（WordPress / Laravel / ThinkPHP）不可选，避免 nginx 把 index.php 当文本返回。先绑定 PHP 再回来选择。" />
        <el-form label-position="top" @submit.prevent="saveRewrite">
          <el-form-item label="规则模板">
            <el-select v-model="rewriteForm.preset" style="width:100%">
              <el-option v-for="p in rewritePresets" :key="p.id" :label="p.label" :value="p.id"
                :disabled="(p.id !== 'none' && (proxyOn(rewriteTarget) || !!rewriteTarget?.redirect_target)) || (p.requires_php && !rewriteTarget?.php_version)" />
            </el-select>
            <div class="mp-hint" style="margin-top:6px">
              {{ rewritePreset(rewriteForm.preset)?.description || "" }}
            </div>
            <div class="mp-hint">
              模板内容固定在面板二进制内，不接受自定义 try_files 或配置片段；保存仍走
              <code class="mp-code">nginx -t</code> → reload，失败会恢复原来的规则。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="rewriteOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveRewrite">应用</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="proxyOpen" :title="'反向代理 · ' + (proxyTarget?.name || '')" width="min(600px, 94vw)">
        <el-alert v-if="rewriteLabel(proxyTarget)" type="info" :closable="false" style="margin-bottom:10px"
          :title="'该站点正在使用伪静态模板（' + rewriteLabel(proxyTarget) + '）：两者都占用 location /。后端会拒绝保存代理；请先把伪静态切回“默认”，再启用代理。'" />
        <el-alert v-if="proxyTarget?.redirect_target" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点正在整站跳转：两者都占用 location /。后端会拒绝保存代理；请先在“整站跳转”对话框里清空跳转目标。" />
        <el-alert v-if="proxyTarget?.hotlink" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用防盗链：静态资源由本机处理。后端会拒绝保存代理；请先在“防盗链”对话框里关闭。" />
        <el-form label-position="top" @submit.prevent="saveProxy">
          <el-form-item label="代理形式（两种都占用 location /，保存一种会清掉另一种）">
            <el-radio-group v-model="proxyForm.mode">
              <el-radio-button value="single">单目标</el-radio-button>
              <el-radio-button value="multi">多上游负载均衡</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-if="proxyForm.mode === 'single'" label="上游 URL（http:// 或 https://，可带端口与路径前缀）">
            <el-input v-model="proxyForm.target" placeholder="http://127.0.0.1:8080" maxlength="255" />
            <div class="mp-hint" style="margin-top:6px">
              只接受一个经过校验的上游地址（主机名 / IP、1-65535 端口、可选的路径前缀）；不接受
              userinfo、查询串、片段或任何 nginx 配置文本。清空输入并保存表示关闭代理，站点回到
              默认的 <code class="mp-code">try_files $uri $uri/ =404</code>。
            </div>
          </el-form-item>
          <template v-else>
            <el-form-item :label="'后端列表（最多 ' + maxProxyUpstreams + ' 个，只接受 http://主机:端口，不带路径）'">
              <div v-for="(u, i) in proxyForm.upstreams" :key="i" style="display:flex;gap:8px;margin-bottom:6px;width:100%">
                <el-input v-model="u.target" placeholder="http://127.0.0.1:3000" maxlength="255" style="flex:1" />
                <el-input-number v-model="u.weight" :min="1" :max="100" :step="1" controls-position="right" style="width:110px" />
                <el-button size="small" text type="danger" :disabled="proxyForm.upstreams.length <= 1" @click="removeUpstream(i)">删除</el-button>
              </div>
              <el-button size="small" :disabled="proxyForm.upstreams.length >= maxProxyUpstreams" @click="addUpstream">添加后端</el-button>
              <div class="mp-hint" style="margin-top:6px">
                权重 1-100，越大分到的请求越多；同一 host:port 不能重复。不支持 https 上游
                （nginx 的 upstream server 只接受 host:port）。删空所有后端并保存表示关闭代理。
                upstream 块由面板写在 http 级的自有表文件里，与 vhost 同一次事务落盘、一起回滚；
                本机 nginx.conf 没有通配 include 时后端会带着理由拒绝，不会写出半份配置。
              </div>
            </el-form-item>
            <el-form-item label="均衡算法">
              <el-select v-model="proxyForm.method" style="width:100%">
                <el-option v-for="m in proxyLBMethods" :key="m.id" :value="m.id" :label="m.label" />
              </el-select>
            </el-form-item>
          </template>
          <el-form-item>
            <el-checkbox v-model="proxyForm.websocket" :disabled="!proxyFilled()">
              转发 WebSocket 升级头（Upgrade / Connection）
            </el-checkbox>
            <div class="mp-hint">
              面板固定写入 <code class="mp-code">proxy_pass</code> 与 Host / X-Real-IP /
              X-Forwarded-For / X-Forwarded-Proto 请求头；勾选后再追加两行升级头。保存仍走
              <code class="mp-code">nginx -t</code> → reload，失败会恢复原来的配置。
              反向代理与伪静态模板互斥；PHP 绑定不受影响（.php 正则 location 优先于 location /）。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="proxyOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy"
            :disabled="proxyFilled() && (!!rewriteLabel(proxyTarget) || !!proxyTarget?.redirect_target || !!proxyTarget?.hotlink)" @click="saveProxy">
            {{ proxyFilled() ? "保存" : "清除代理" }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="redirectOpen" :title="'整站跳转 · ' + (redirectTarget?.name || '')" width="min(600px, 94vw)">
        <el-alert v-if="rewriteLabel(redirectTarget)" type="info" :closable="false" style="margin-bottom:10px"
          :title="'该站点正在使用伪静态模板（' + rewriteLabel(redirectTarget) + '）：两者都占用 location /。后端会拒绝保存跳转；请先把伪静态切回“默认”。'" />
        <el-alert v-if="proxyOn(redirectTarget)" type="info" :closable="false" style="margin-bottom:10px"
          :title="'该站点已启用反向代理：两者都占用 location /。后端会拒绝保存跳转；请先在“代理”对话框里清空上游 URL。'" />
        <el-alert v-if="redirectTarget?.hotlink" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用防盗链：静态资源由本机处理。后端会拒绝保存跳转；请先在“防盗链”对话框里关闭。" />
        <el-form label-position="top" @submit.prevent="saveRedirect">
          <el-form-item label="跳转目标（http:// 或 https:// 绝对 URL）">
            <el-input v-model="redirectForm.target" placeholder="https://new.example.com" maxlength="255" />
            <div class="mp-hint" style="margin-top:6px">
              只接受一个经过校验的绝对地址（主机名 / IP、1-65535 端口、可选的路径前缀）；
              不接受 userinfo、查询串、片段或任何 nginx 配置文本。清空输入并保存表示关闭跳转，
              站点回到默认的 <code class="mp-code">try_files $uri $uri/ =404</code>。
            </div>
          </el-form-item>
          <el-form-item label="状态码">
            <el-radio-group v-model="redirectForm.code" :disabled="!redirectForm.target.trim()">
              <el-radio-button :value="301">301 永久</el-radio-button>
              <el-radio-button :value="302">302 临时</el-radio-button>
            </el-radio-group>
            <div class="mp-hint">
              面板固定写入一行 <code class="mp-code">return &lt;code&gt; &lt;target&gt;;</code>，
              不接受任何自定义配置文本。
            </div>
          </el-form-item>
          <el-form-item>
            <el-checkbox v-model="redirectForm.keep_path" :disabled="!redirectForm.target.trim()">
              保留原请求路径（拼接 $request_uri）
            </el-checkbox>
            <div class="mp-hint">
              勾选后请求 <code class="mp-code">/a/b?x=1</code> 会跳到目标地址的同一路径与查询串，
              适合"换域名但保留路径"；目标尾部斜杠会被去掉，避免出现双斜杠。
              保存仍走 <code class="mp-code">nginx -t</code> → reload，失败会恢复原来的 location /。
              整站跳转与伪静态模板、反向代理三者互斥，PHP 绑定不受影响。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="redirectOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy"
            :disabled="!!redirectForm.target.trim() && (!!rewriteLabel(redirectTarget) || proxyOn(redirectTarget) || !!redirectTarget?.hotlink)" @click="saveRedirect">
            {{ redirectForm.target.trim() ? "保存" : "清除跳转" }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="redirectPathsOpen" :title="'按路径跳转 · ' + (redirectPathsTarget?.name || '')" width="min(760px, 96vw)">
        <el-alert v-if="redirectPathsTarget?.redirect_paths?.length" type="info" :closable="false" style="margin-bottom:10px"
          :title="'该站点已有 ' + redirectPathsTarget.redirect_paths.length + ' 条路径例外。保存会用下面的列表整体替换；删除全部行后保存表示清除。'" />
        <div class="mp-row" style="margin-bottom:8px;align-items:flex-end">
          <div style="flex:1;min-width:200px"><span class="mp-muted mp-tiny">精确路径（区分大小写）</span></div>
          <div style="width:110px"><span class="mp-muted mp-tiny">状态码</span></div>
          <div style="flex:2;min-width:220px"><span class="mp-muted mp-tiny">跳转目标</span></div>
          <div style="width:52px"></div>
        </div>
        <div v-for="(rule, i) in redirectPathRules" :key="i" class="mp-row" style="margin-bottom:8px">
          <el-input v-model="rule.path" maxlength="128" placeholder="/old" style="flex:1;min-width:200px" />
          <el-select v-model="rule.code" style="width:110px">
            <el-option label="301 永久" :value="301" />
            <el-option label="302 临时" :value="302" />
          </el-select>
          <el-input v-model="rule.target" maxlength="255" placeholder="https://new.example.com" style="flex:2;min-width:220px" />
          <el-button size="small" text type="danger" :disabled="busy" @click="removeRedirectPath(i)">删除</el-button>
        </div>
        <div class="mp-hint" style="margin-top:4px">
          每行渲染成一个固定的 <code class="mp-code">location = &lt;path&gt;</code> 块；请求带查询串时，
          面板追加常量 <code class="mp-code">$is_args$args</code> 原样保留它。精确路径优先于
          <code class="mp-code">location /</code>，所以本表可与整站跳转、反向代理、伪静态、访问密码与
          PHP 绑定共存；两者互不遮蔽各自的范围。站点根路径 <code class="mp-code">/</code> 不在这里配置。
          路径不能包含 <code class="mp-code">..</code>，也不能遮蔽 <code class="mp-code">/.well-known/acme-challenge</code>。
          目标地址与整站跳转同样校验，只能填绝对 <code class="mp-code">http://</code> 或
          <code class="mp-code">https://</code> 地址，不接受任何 nginx 配置文本。
        </div>
        <div class="mp-row" style="margin-top:8px">
          <el-button size="small" :disabled="busy || redirectPathRules.length >= maxRedirectPathRules" @click="addRedirectPath">
            添加一行
          </el-button>
          <span class="mp-muted mp-tiny">最多 {{ maxRedirectPathRules }} 条 · 当前 {{ redirectPathRules.length }} 条</span>
        </div>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="redirectPathsOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveRedirectPaths">
            {{ redirectPathRules.some((r) => String(r.path || '').trim() || String(r.target || '').trim()) ? "保存" : "清除跳转表" }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="errorPagesOpen" :title="'自定义错误页 · ' + (errorPagesTarget?.name || '')" width="min(700px, 96vw)">
        <el-alert v-if="errorPagesTarget?.error_pages?.length" type="info" :closable="false" style="margin-bottom:10px"
          :title="'该站点已有 ' + errorPagesTarget.error_pages.length + ' 条自定义错误页。保存会用下面的列表整体替换；删除全部行后保存表示清除。'" />
        <div class="mp-row" style="margin-bottom:8px;align-items:flex-end">
          <div style="width:130px"><span class="mp-muted mp-tiny">状态码</span></div>
          <div style="flex:1;min-width:220px"><span class="mp-muted mp-tiny">站内路径（相对站点根目录）</span></div>
          <div style="width:52px"></div>
        </div>
        <div v-for="(rule, i) in errorPageRules" :key="i" class="mp-row" style="margin-bottom:8px">
          <el-select v-model="rule.code" style="width:130px">
            <el-option v-for="c in errorPageCodes" :key="c" :label="String(c)" :value="c" />
          </el-select>
          <el-input v-model="rule.path" maxlength="128" placeholder="/404.html" style="flex:1;min-width:220px" />
          <el-button size="small" text type="danger" :disabled="busy" @click="removeErrorPage(i)">删除</el-button>
        </div>
        <div class="mp-hint" style="margin-top:4px">
          每行渲染成一条固定的 server 级 <code class="mp-code">error_page &lt;code&gt; &lt;path&gt;;</code> 指令，
          外加每个错误页路径一个精确静态 <code class="mp-code">location =</code> 块——反代或整站跳转站点
          的错误页因此仍从站点根目录提供，不会被 <code class="mp-code">location /</code> 吞掉。
          它与整站跳转、按路径跳转、反向代理、伪静态、访问密码、目录列表与 PHP 绑定共存，
          但路径不能与按路径跳转表的同名例外重复（后端会说明理由并拒绝）。错误页文件需要你自己放在站点根目录下
          （如 <code class="mp-code">{{ errorPagesTarget?.root || '' }}/404.html</code>）；
          文件缺失时 nginx 回退到内置错误页，不会因此 500。它只替换 nginx 本机产生的错误：
          反向代理站点的上游错误响应原样透传，面板不开启 <code class="mp-code">proxy_intercept_errors</code>。
          路径不能包含 <code class="mp-code">..</code>，也不能遮蔽 <code class="mp-code">/.well-known/acme-challenge</code>，
          不接受任何 nginx 配置文本。
        </div>
        <div class="mp-row" style="margin-top:8px">
          <el-button size="small" :disabled="busy || errorPageRules.length >= maxErrorPageRules" @click="addErrorPage">
            添加一行
          </el-button>
          <span class="mp-muted mp-tiny">最多 {{ maxErrorPageRules }} 条 · 当前 {{ errorPageRules.length }} 条</span>
        </div>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="errorPagesOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveErrorPages">
            {{ errorPageRules.some((r) => String(r.path || '').trim()) ? "保存" : "清除错误页" }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="limitOpen" :title="'流量限制 · ' + (limitTarget?.name || '')" width="min(620px, 94vw)">
        <el-alert v-if="limitTarget?.limits" type="info" :closable="false" style="margin-bottom:10px"
          :title="'该站点当前限流：' + limitLabel(limitTarget) + '。四个字段全部留空并保存即可清除。'" />
        <el-form label-position="top" @submit.prevent="saveLimit">
          <el-form-item label="请求速率上限（如 10r/s、200r/m、100r）">
            <el-input v-model="limitForm.request_rate" maxlength="16" placeholder="留空表示不做速率限制"
              style="width:260px" />
            <div class="mp-hint" style="margin-top:4px">
              面板按 <code class="mp-code">$binary_remote_addr</code>（单个客户端 IP）统计请求速率，
              超出后按下面的状态码拒绝。速率由后端解析与规范化，只接受
              <code class="mp-code">r/s</code>、<code class="mp-code">r/m</code> 或裸数字（每秒）形状。
            </div>
          </el-form-item>
          <el-form-item label="突发（burst，仅在设置了速率时有效）">
            <el-input v-model="limitForm.burst" maxlength="7" placeholder="如 20；留空则不写 burst"
              style="width:200px" />
            <div class="mp-hint" style="margin-top:4px">
              面板渲染 burst 时固定附带 <code class="mp-code">nodelay</code>：允许的突发请求立即放行，
              超出部分才排队或拒绝。这个开关不由页面控制。
            </div>
          </el-form-item>
          <el-form-item label="单 IP 并发连接数上限">
            <el-input v-model="limitForm.connections" maxlength="7" placeholder="如 5；留空表示不限制连接数"
              style="width:200px" />
          </el-form-item>
          <el-form-item label="超限时返回的状态码">
            <el-select v-model="limitForm.status" style="width:220px">
              <el-option v-for="opt in limitStatuses" :key="opt.value" :label="opt.label" :value="opt.value" />
            </el-select>
            <div class="mp-hint" style="margin-top:4px">
              只支持 429 与 503；留空沿用 nginx 默认的 503。
            </div>
          </el-form-item>
          <div class="mp-hint">
            速率、连接数至少要给出一个，否则突发与状态码没有作用，后端会返回 400。nginx 要求
            共享内存区（zone）定义在 http 上下文，因此面板会在同一次 <code class="mp-code">nginx -t</code>
            通过后才 reload 的事务里，同时写站点 vhost 与一张它自有的 http 级表文件；任一步失败两个文件
            一起恢复原样。表里只允许面板存在限流的站点，最后一个限流清除时该文件会被删除。
            本机 nginx.conf 若没有通配形式的 http 级 include，后端不会猜测位置，直接返回带理由的 400。
          </div>
          <div class="mp-hint">
            限流是 server 级指令，不占用 <code class="mp-code">location /</code>，可与伪静态、代理、
            整站跳转、按路径跳转、防盗链、访问密码、真实 IP 与 PHP 绑定共存。
          </div>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="limitOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveLimit">
            {{ limitForm.request_rate.trim() || limitForm.connections.trim() || limitForm.status.trim() || limitForm.burst.trim() ? "保存" : (limitTarget?.limits ? "清除限流" : "保存") }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="metaOpen" :title="'分组 / 备注 · ' + (metaTarget?.name || '')" width="min(600px, 94vw)">
        <el-form label-position="top" @submit.prevent="saveMeta">
          <el-form-item label="分组（可留空）">
            <el-input v-model="metaForm.group" maxlength="64" placeholder="如 电商 / 测试站 / 客户 A"
              style="width:260px" />
            <div class="mp-hint" style="margin-top:4px">
              单行标签，最长 64 个字符。分组只影响这个列表的展示与筛选，不会写进 nginx。
            </div>
          </el-form-item>
          <el-form-item label="备注（可留空）">
            <el-input v-model="metaForm.note" type="textarea" :rows="3" maxlength="500" show-word-limit
              placeholder="给自己看的说明，例如“双 11 后要扩容”" />
            <div class="mp-hint" style="margin-top:4px">
              最长 500 个字符，可换行。备注存在面板数据库里，不进 vhost、不进站点标记，删除站点时一并清除。
              两项都留空并保存即清除该站点的分组与备注。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="metaOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveMeta">
            {{ metaForm.group.trim() || metaForm.note.trim() ? "保存" : (metaTarget?.group || metaTarget?.note ? "清除" : "保存") }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="logOpen" :title="'站点日志 · ' + (logTarget?.name || '')" width="min(860px, 96vw)">
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
          <el-radio-group v-model="logKind" size="small" @change="loadLog">
            <el-radio-button value="access">访问日志</el-radio-button>
            <el-radio-button value="error">错误日志</el-radio-button>
          </el-radio-group>
          <el-select v-model="logLines" size="small" style="width:120px" @change="loadLog">
            <el-option :value="100" label="尾 100 行" />
            <el-option :value="200" label="尾 200 行" />
            <el-option :value="500" label="尾 500 行" />
          </el-select>
          <el-button size="small" :loading="logLoading" @click="loadLog">刷新</el-button>
          <span v-if="logData" class="mp-muted mp-tiny">
            {{ logData.path }} · {{ logData.size }} 字节
            <template v-if="logData.truncated"> · 只显示尾部，更早的内容未加载</template>
          </span>
        </div>
        <el-alert v-if="logData && !logData.exists" type="info" :closable="false"
          title="该站点的这个日志文件还不存在：vhost 已带按站点日志指令，但迁移后还没有请求写进来。产生访问或错误后刷新即可看到。" />
        <pre v-else-if="logData && logData.lines.length" class="mp-logtail">{{ logData.lines.join("\n") }}</pre>
        <div v-else-if="logData" class="mp-muted">日志文件存在但暂时没有内容。</div>
        <div v-else-if="logLoading" class="mp-muted">读取中…</div>
        <template #footer>
          <el-button size="small" @click="logOpen = false">关闭</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="hotlinkOpen" :title="'防盗链 · ' + (hotlinkTarget?.name || '')" width="min(620px, 94vw)">
        <el-alert v-if="proxyOn(hotlinkTarget)" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点正在使用反向代理：静态资源不在本机，防盗链无从生效。后端会拒绝启用；请先在“代理”对话框里清空上游 URL。" />
        <el-alert v-if="hotlinkTarget?.redirect_target" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点正在整站跳转：静态资源由目标站点提供。后端会拒绝启用；请先在“整站跳转”对话框里清空跳转目标。" />
        <el-form label-position="top" @submit.prevent="saveHotlink">
          <el-form-item label="静态资源 Referer 校验">
            <el-switch v-model="hotlinkForm.enabled" active-text="启用" inactive-text="关闭" />
            <div class="mp-hint" style="margin-top:6px">
              启用后写入一个固定的正则 location，覆盖图片、样式、脚本、字体与影音扩展名
              （jpg / png / webp / svg / css / js / woff2 / mp4 / mp3 等）；扩展名表和
              <code class="mp-code">valid_referers</code> 参数都在后端常量里，页面不提供自定义片段。
            </div>
          </el-form-item>
          <el-form-item>
            <el-checkbox v-model="hotlinkForm.allow_empty" :disabled="!hotlinkForm.enabled">
              放行不带 Referer 的请求（地址栏直接打开、命令行与隐私浏览器）
            </el-checkbox>
            <div class="mp-hint">
              勾选时写入 <code class="mp-code">valid_referers none blocked server_names;</code>；
              不勾选时只写 <code class="mp-code">server_names</code>，每个静态资源请求都必须带本站来源。
              命中
              <code class="mp-code">$invalid_referer</code> 的请求返回 403。
            </div>
            <div class="mp-hint">
              防盗链与反向代理、整站跳转互斥（后两者让本机静态资源块不可达）；伪静态模板与 PHP
              绑定不受影响。保存仍走 <code class="mp-code">nginx -t</code> → reload，失败会恢复原配置。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="hotlinkOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy"
            :disabled="hotlinkForm.enabled && (proxyOn(hotlinkTarget) || !!hotlinkTarget?.redirect_target)" @click="saveHotlink">
            {{ hotlinkForm.enabled ? "保存" : (hotlinkTarget?.hotlink ? "关闭防盗链" : "保存") }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="authOpen" :title="'访问密码 · ' + (authTarget?.name || '')" width="min(620px, 94vw)">
        <el-alert v-if="authTarget?.auth_user" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用访问密码。口令不会从后端读回：只改用户名或更换口令都要重新输入一次口令；两项都留空则关闭。" />
        <el-form label-position="top" @submit.prevent="saveAuth">
          <el-form-item label="用户名">
            <el-input v-model="authForm.username" maxlength="32" placeholder="例如 guest"
              autocomplete="off" style="width:260px" />
            <div class="mp-hint" style="margin-top:4px">
              1-32 位字母、数字、点、下划线或连字符，且以字母或数字开头。
            </div>
          </el-form-item>
          <el-form-item label="口令（8-128 个字符）">
            <el-input v-model="authForm.password" type="password" show-password maxlength="128"
              placeholder="保存时必填；不会回显，也不会写进 nginx 配置" autocomplete="new-password"
              style="width:320px" />
            <div class="mp-hint" style="margin-top:4px">
              后端把它写成 <code class="mp-code">{SHA}</code>（base64(SHA-1)）行，存进面板管理的
              0600 口令文件；vhost 里只有 <code class="mp-code">auth_basic</code> 与
              <code class="mp-code">auth_basic_user_file</code> 两条固定指令，不接受自定义片段。
            </div>
            <div class="mp-hint">
              访问密码整站生效，不占用 <code class="mp-code">location /</code>，可与伪静态、代理、
              跳转、防盗链和 PHP 绑定共存；HTTPS 站点的 ACME 续期路径会自动豁免口令。
            </div>
            <div class="mp-hint">
              {SHA} 是无盐快速摘要，只用于挡住随手访问，不是强口令存储；口令文件权限为 0600。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="authOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveAuth">
            {{ authForm.username ? "保存" : (authTarget?.auth_user ? "关闭访问密码" : "保存") }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="configOpen" :title="'配置文件 · ' + (configTarget?.name || '')" width="min(860px, 96vw)">
        <el-alert type="warning" :closable="false" style="margin-bottom:10px"
          title="两条边界：① # minipanel-site: 标记行必须原样保留且只有一行，删改会被拒绝——域名、根目录等请用对应功能页修改；② 后续任何面板功能写入（改域名、切 PHP、设代理等）都会按标记重新生成整份配置，手工添加的指令会被覆盖。" />
        <div class="mp-muted mp-tiny" style="margin-bottom:6px"><code class="mp-code">{{ configForm.path }}</code></div>
        <el-input v-model="configForm.content" type="textarea" :rows="22" spellcheck="false"
          style="font-family:monospace" />
        <div class="mp-hint" style="margin-top:6px">
          保存走与功能写入相同的事务：写文件 → <code class="mp-code">nginx -t</code> → 通过才 reload，
          失败恢复原字节并原样显示 nginx 的拒绝理由；内容未变化时不触发 reload。最多 65536 字节。
          标记之外的指令由你负责，面板不逐条解析。
        </div>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="configOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy"
            :disabled="configForm.content === configForm.original" @click="saveConfig">保存</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="corsOpen" :title="'CORS 跨域 · ' + (corsTarget?.name || '')" width="min(640px, 94vw)">
        <el-alert v-if="corsTarget?.cors?.origins?.length" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用 CORS。清空来源列表并保存即可关闭，跨域响应头与 OPTIONS 短路一并移除。" />
        <el-form label-position="top" @submit.prevent="saveCors">
          <el-form-item label="允许的来源（每行一条，最多 10 条；单独一行 * 表示任意来源）">
            <el-input v-model="corsForm.origins" type="textarea" :rows="4"
              placeholder="https://app.example.com&#10;http://localhost:5173" />
            <div class="mp-hint" style="margin-top:6px">
              只接受精确的 <code class="mp-code">scheme://主机[:端口]</code>（http/https，不带路径）；
              <code class="mp-code">*</code> 不能与其它来源混用。未列出的来源得不到
              <code class="mp-code">Access-Control-Allow-Origin</code> 头，并附 <code class="mp-code">Vary: Origin</code>。
            </div>
          </el-form-item>
          <el-form-item label="允许的方法（不勾选默认 GET / HEAD / POST）">
            <el-checkbox-group v-model="corsForm.methods">
              <el-checkbox v-for="m in corsMethodOptions" :key="m" :value="m">{{ m }}</el-checkbox>
            </el-checkbox-group>
          </el-form-item>
          <el-form-item label="允许的请求头（逗号分隔，最多 20 个；留空反射预检请求头）">
            <el-input v-model="corsForm.headers" placeholder="Content-Type, Authorization" />
          </el-form-item>
          <el-form-item>
            <el-checkbox v-model="corsForm.credentials" :disabled="corsForm.origins.trim() === '*'">
              允许携带凭据（Cookie / HTTP 认证）
            </el-checkbox>
            <el-input-number v-model="corsForm.maxAge" :min="0" :max="86400" :step="60" controls-position="right" style="margin-left:16px" />
            <span class="mp-hint" style="margin-left:8px">预检缓存秒数（0 表示不下发）</span>
            <div class="mp-hint">
              浏览器禁止 <code class="mp-code">*</code> 来源携带凭据，后端会直接拒绝该组合。
              开启期间 OPTIONS 预检由本机直接回 204，<b>不再转发到上游</b>；面板也不会隐藏上游
              自己返回的 CORS 头，上游同样发 CORS 头时请关掉其中一边，否则浏览器会看到重复值。
              它是 server 级固定头，不占用 <code class="mp-code">location /</code>，与代理、跳转、
              伪静态等全部站点功能共存；强制 HTTPS 站点请让前端直接使用 https 来源。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="corsOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveCors">
            {{ corsForm.origins.trim() ? "保存" : (corsTarget?.cors?.origins?.length ? "关闭 CORS" : "保存") }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="realOpen" :title="'真实 IP 解析 · ' + (realTarget?.name || '')" width="min(620px, 94vw)">
        <el-alert v-if="realTarget?.real_ip_from?.length" type="info" :closable="false" style="margin-bottom:10px"
          title="该站点已启用可信代理解析。清空下面的列表并保存即可关闭，站点恢复直接使用对端地址。" />
        <el-form label-position="top" @submit.prevent="saveRealIP">
          <el-form-item label="可信代理地址或网段（每行一条，最多 16 条）">
            <el-input v-model="realForm.from" type="textarea" :rows="4"
              placeholder="10.0.0.0/8&#10;192.0.2.7" />
            <div class="mp-hint" style="margin-top:6px">
              只有来自这些地址/网段的请求才会读取转发头；<code class="mp-code">0.0.0.0/0</code> 与
              <code class="mp-code">::/0</code> 会被后端拒绝，因为那等于允许任何客户端伪造来源地址。
            </div>
          </el-form-item>
          <el-form-item label="转发头">
            <el-radio-group v-model="realForm.header">
              <el-radio value="X-Forwarded-For">X-Forwarded-For（可递归）</el-radio>
              <el-radio value="X-Real-IP">X-Real-IP（单个地址）</el-radio>
            </el-radio-group>
            <div class="mp-hint">
              选择 X-Forwarded-For 时后端额外写 <code class="mp-code">real_ip_recursive on</code>；
              X-Real-IP 不写。转发头只影响站点日志与后续按 IP 的规则，不改变面板自身的来源判断。
            </div>
            <div class="mp-hint">
              真实 IP 解析是 server 级指令，不占用 <code class="mp-code">location /</code>，可与伪静态、
              代理、跳转、防盗链、访问密码和 PHP 绑定共存。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="realOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveRealIP">
            {{ realForm.from.trim() ? "保存" : (realTarget?.real_ip_from?.length ? "关闭真实 IP" : "保存") }}
          </el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="phpOpen" :title="'PHP · ' + (phpTarget?.name || '')" width="min(520px, 94vw)">
        <el-alert v-if="!phpAvailable" type="info" :closable="false" style="margin-bottom:10px"
          :title="phpSwitchFeat?.reason || '本机没有可绑定的 php-fpm 版本。'" />
        <el-form label-position="top" @submit.prevent="savePHP">
          <el-form-item label="执行 PHP 的版本">
            <el-select v-model="phpForm.version" style="width:100%">
              <el-option label="静态（不执行 PHP）" value="" />
              <el-option v-for="v in phpVersions" :key="v" :label="'PHP ' + v + '（fpm）'" :value="v" />
            </el-select>
            <div class="mp-hint" style="margin-top:6px">
              只会写入该版本的 unix socket 到 vhost；面板不创建 php-fpm 池，也不启动服务。
              保存后 nginx 先 <code class="mp-code">-t</code> 再 reload，失败会恢复原绑定。
            </div>
            <div v-if="phpForm.version && phpTarget?.php_version === phpForm.version && !phpSocketOk(phpTarget)" class="mp-hint">
              当前 socket 状态：{{ phpSocketWords(phpTarget) }}；保存后站点会返回 502，先启动
              PHP {{ phpForm.version }} 的 fpm。
            </div>
            <div v-if="phpTarget && rewritePreset(phpTarget.rewrite)?.requires_php" class="mp-hint">
              当前站点使用 {{ rewriteLabel(phpTarget) }} 伪静态模板，回退目标是 index.php；清空 PHP
              会被后端拒绝。先把伪静态切回“默认”或“单页应用”，再解绑。
            </div>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="phpOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="savePHP">应用</el-button>
        </template>
      </el-dialog>

      <el-dialog v-model="tlsOpen" :title="'HTTPS · ' + (tlsTarget?.name || '')" width="min(640px, 94vw)">
        <el-alert v-if="sslFeat && sslFeat.state !== 'available'" type="info" :closable="false" style="margin-bottom:10px"
          :title="sslFeat.reason || ''" />
        <el-form label-position="top" @submit.prevent="saveTLS">
          <el-form-item label="证书来源">
            <el-radio-group v-model="tlsForm.mode">
              <el-radio value="acme" :disabled="!acmeUsable">
                ACME 自动签发（Let's Encrypt，到期前自动续期）
              </el-radio>
              <el-radio value="selfsigned">生成自签证书（适合内网 / 测试）</el-radio>
              <el-radio value="upload">上传证书链与私钥</el-radio>
            </el-radio-group>
            <div v-if="hasWildcard" class="mp-hint" style="margin-top:6px">
              该站点含通配符域名（如 *.example.com）。HTTP-01 无法验证通配符，请上传包含该 SAN 的证书；
              DNS-01 自动签发尚未交付。
            </div>
            <div v-else-if="tlsForm.mode === 'acme'" class="mp-hint" style="margin-top:6px">
              CA 会从公网访问该域名的 80 端口 <code class="mp-code">/.well-known/acme-challenge/</code>。
              请确认域名已解析到本机、80 端口可达；签发通常需要几十秒。强制 HTTPS 时，这个挑战路径
              不会被 301 到 443，否则证书将无法续期。
            </div>
          </el-form-item>
          <template v-if="tlsForm.mode === 'upload'">
            <el-form-item label="证书链 PEM（fullchain）">
              <el-input v-model="tlsForm.cert_pem" type="textarea" :rows="4" placeholder="-----BEGIN CERTIFICATE-----" />
              <input type="file" accept=".pem,.crt,.cer,.txt" @change="pickPEM($event, 'cert_pem')" />
            </el-form-item>
            <el-form-item label="私钥 PEM（不要上传带口令的私钥）">
              <el-input v-model="tlsForm.key_pem" type="textarea" :rows="4" placeholder="-----BEGIN PRIVATE KEY-----" />
              <input type="file" accept=".pem,.key,.txt" @change="pickPEM($event, 'key_pem')" />
            </el-form-item>
            <div class="mp-hint" style="margin-bottom:10px">
              后端会校验证书与私钥配对、当前时间在有效期内、证书覆盖站点域名（通配符按精确 SAN 匹配）；
              不通过时不会写入磁盘，也不会 reload nginx。
            </div>
          </template>
          <el-form-item>
            <el-checkbox v-model="tlsForm.redirect">把 HTTP 301 跳转到 HTTPS</el-checkbox>
          </el-form-item>
        </el-form>
        <template #footer>
          <el-button size="small" :disabled="busy" @click="tlsOpen = false">取消</el-button>
          <el-button size="small" type="primary" :loading="busy" @click="saveTLS">应用</el-button>
        </template>
      </el-dialog>

      <div class="mp-hint">
        证书来源：ACME HTTP-01 自动签发与续期、手工上传、自签。通配符证书仍需上传（DNS-01
        尚未交付）；手工上传与自签证书不会被自动替换。PHP 版本绑定使用各版本已有的 fpm socket，
        不创建独立 pool；多版本安装/卸载仍是后续片，能力位图里的
        <code class="mp-code">php</code> 仍为 degraded。站点的域名、根目录、默认文档与伪静态模板可以
        随时编辑，域名变更受现有证书覆盖范围约束。伪静态模板由本地二进制提供
        （WordPress / Laravel / ThinkPHP / SPA），不接受自定义配置片段；需要 PHP 的模板只能用于
        已绑定 PHP 的站点。反向代理同样只接受一个校验过的上游 URL（可选 WebSocket），
        固定写入代理头，与伪静态模板互斥。按路径跳转只写若干条精确 <code class="mp-code">location =</code>
        例外，保留查询串且不占用 <code class="mp-code">location /</code>，所以能够与整站跳转、代理和
        伪静态共存。流量限制只收速率、突发、单 IP 连接数与超限状态码四个值，zone 名与键都由
        后端固定；它写 vhost 的同时会在同一次事务里维护一张面板自有的 http 级 zone 表，本机
        nginx.conf 没有通配 include 时后端拒绝并说明原因。分组与备注是唯一不碰 nginx 的站点控制：
        它只写进面板自己的 SQLite、列表按站点名 join 回来，不进 vhost 也不进 marker，删除站点时一并
        清除；顶部的搜索框与分组下拉在这份已加载的列表上做即时过滤，不再打后端。新建站点的根目录是 0755 的空目录，
        放一个 <code class="mp-code">index.html</code>（或绑定 PHP 后放 index.php）就能访问。
      </div>
    </template>
  </div>
</template>

<style scoped>
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--mp-line); vertical-align: top; }
thead th { color: var(--mp-muted); font-weight: 500; white-space: nowrap; }
tr:last-child th, tr:last-child td { border-bottom: 0; }
.mp-code { white-space: pre-wrap; word-break: break-all; }
.mp-logtail { max-height: 52vh; overflow: auto; background: var(--mp-bg, #f6f7f9); border: 1px solid var(--mp-line); border-radius: 6px; padding: 10px; font-size: 12px; line-height: 1.5; white-space: pre-wrap; word-break: break-all; margin: 0; }
.mp-note-cell { max-width: 340px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; word-break: break-word; }
</style>
