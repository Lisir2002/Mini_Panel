<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { store } from "../store";

// M2 第三、四、六、七、八片：静态站点、站点证书、PHP 版本绑定、基础设置编辑与伪静态模板。
// 这一页的边界与后端能力位图是同一句话，不另写一套：
//   * site / site_write 由 Detect() 现场决定（装了 nginx、进程是 root、配置目录可识别）。
//     不可用时这页只显示后端给的理由与 fix_action，不画一个点了没反应的"新建"按钮。
//   * 编辑对话框替换域名、根目录与默认文档。域名变更时后端先用现有证书校验新域名集合，
//     覆盖不了就返回 422 invalid_tls 且不写文件——页面原样显示理由，不假装保存成功。
//   * php_version_switch 只列出 php_fpm_versions；选择后由后端把版本解析成 socket。
//     socket 当前不是 listening 时，页面直接说"站点会 502"，不把配置写入说成后端可用。
//   * 伪静态列表来自 GET /sites/rewrite-presets，不是前端硬编码；模板内容固定在二进制里。
//     wordpress / laravel / thinkphp 需要已绑定 PHP，静态站点会被后端拒绝。
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

onMounted(load);
</script>

<template>
  <div class="mp-card">
    <h3>网站</h3>
    <p class="mp-note">
      管理面板自己创建的站点；可以在创建时或之后绑定一个本机探测到的 PHP fpm 版本，留空则是
      <b>静态站点</b>。站点的域名、根目录、默认文档与伪静态模板可随时编辑。每一次创建、编辑、删除、
      PHP 切换、伪静态或证书变更都是"先测试后生效"：写配置 →
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

      <div class="mp-row" style="margin:14px 0 10px">
        <el-button size="small" :loading="busy" @click="load">刷新</el-button>
        <span class="mp-muted mp-tiny">共 {{ rows.length }} 个由面板管理的站点</span>
      </div>

      <table>
        <thead>
          <tr><th>站点</th><th>域名</th><th>根目录</th><th>状态</th><th>PHP</th><th>HTTPS</th><th>创建时间</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.name">
            <td><b>{{ r.name }}</b><div class="mp-muted mp-tiny"><code class="mp-code">{{ r.config_path }}</code></div></td>
            <td><span class="mp-clip" :title="r.domains.join(' ')">{{ r.domains.join(" · ") }}</span></td>
            <td>
              <code class="mp-code">{{ r.root }}</code>
              <div v-if="r.index?.length" class="mp-muted mp-tiny">index {{ r.index.join(" ") }}</div>
              <div v-if="rewriteLabel(r)" class="mp-muted mp-tiny">伪静态 · {{ rewriteLabel(r) }}</div>
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
            <td style="width:280px;white-space:nowrap">
              <el-button size="small" text type="primary" @click="openEdit(r)">编辑</el-button>
              <el-button size="small" text type="primary" @click="openRewrite(r)">伪静态</el-button>
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
        <el-alert v-if="rewriteTarget && !rewriteTarget.php_version" type="info" :closable="false" style="margin-bottom:10px"
          title="当前是静态站点：需要 PHP 的模板（WordPress / Laravel / ThinkPHP）不可选，避免 nginx 把 index.php 当文本返回。先绑定 PHP 再回来选择。" />
        <el-form label-position="top" @submit.prevent="saveRewrite">
          <el-form-item label="规则模板">
            <el-select v-model="rewriteForm.preset" style="width:100%">
              <el-option v-for="p in rewritePresets" :key="p.id" :label="p.label" :value="p.id"
                :disabled="p.requires_php && !rewriteTarget?.php_version" />
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
        已绑定 PHP 的站点。新建站点的根目录是 0755 的空目录，
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
</style>
