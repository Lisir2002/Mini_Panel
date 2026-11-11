<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { store } from "../store";

// M2 第三片：静态站点。这一页的边界与后端能力位图是同一句话，不另写一套：
//   * site / site_write 由 Detect() 现场决定（装了 nginx、进程是 root、配置目录可识别）。
//     不可用时这页只显示后端给的理由与 fix_action，不画一个点了没反应的"新建"按钮。
//   * 这里创建的是纯静态站点：没有 PHP 绑定、没有证书签发。php 仍是 degraded、
//     ssl 仍是 unavailable，页面上不做"以后会有"的暗示。
//   * 删除只删配置与软链接，网站根目录故意保留——删 vhost 不是删数据。
const state = ref(null);
const error = ref("");
const msg = ref("");
const busy = ref(false);
const form = ref({ name: "", domains: "", root: "" });

const siteFeat = computed(() => store.caps?.features?.site || null);
const siteWriteFeat = computed(() => store.caps?.features?.site_write || null);
const available = computed(() => siteFeat.value?.state === "available" && siteWriteFeat.value?.state === "available");
const feats = computed(() => [siteFeat.value, siteWriteFeat.value].filter(Boolean));
const rows = computed(() => state.value?.items || []);

function parseDomains(text) {
  return String(text || "")
    .split(/[\s,，;；]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

async function load() {
  error.value = "";
  if (!available.value) return;
  try { state.value = await api("/api/v1/sites"); }
  catch (e) { error.value = e.message; }
}

async function create() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const body = { name: form.value.name.trim(), domains: parseDomains(form.value.domains) };
    const root = form.value.root.trim();
    if (root) body.root = root;
    const site = await api("/api/v1/sites", { method: "POST", body: JSON.stringify(body) });
    msg.value = "已创建 " + site.name + "，nginx 已通过 nginx -t 并重载。";
    form.value = { name: "", domains: "", root: "" };
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

onMounted(load);
</script>

<template>
  <div class="mp-card">
    <h3>网站</h3>
    <p class="mp-note">
      管理面板自己创建的 <b>静态站点</b>。每一次创建或删除都是"先测试后生效"：写配置 →
      <code class="mp-code">nginx -t</code> → 只有通过才 reload；任何一步失败都会恢复上一份配置。
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
        <el-button type="primary" size="small" :loading="busy" @click="create">创建静态站点</el-button>
      </el-form>

      <div class="mp-row" style="margin:14px 0 10px">
        <el-button size="small" :loading="busy" @click="load">刷新</el-button>
        <span class="mp-muted mp-tiny">共 {{ rows.length }} 个由面板管理的站点</span>
      </div>

      <table>
        <thead>
          <tr><th>站点</th><th>域名</th><th>根目录</th><th>状态</th><th>创建时间</th><th></th></tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.name">
            <td><b>{{ r.name }}</b><div class="mp-muted mp-tiny"><code class="mp-code">{{ r.config_path }}</code></div></td>
            <td><span class="mp-clip" :title="r.domains.join(' ')">{{ r.domains.join(" · ") }}</span></td>
            <td><code class="mp-code">{{ r.root }}</code></td>
            <td>
              <span class="mp-tag on" v-if="r.enabled">已启用</span>
              <span class="mp-tag flat" v-else>未启用</span>
            </td>
            <td class="mp-muted mp-tiny">{{ r.created_at }}</td>
            <td style="width:90px">
              <el-popconfirm title="删除这个站点的配置？网站根目录会保留。" confirm-button-text="确认删除"
                cancel-button-text="取消" confirm-button-type="danger" width="280" @confirm="remove(r.name)">
                <template #reference>
                  <el-button size="small" text type="danger">删除</el-button>
                </template>
              </el-popconfirm>
            </td>
          </tr>
          <tr v-if="!rows.length"><td colspan="6" class="mp-muted">还没有由面板创建的站点。</td></tr>
        </tbody>
      </table>

      <div class="mp-hint">
        本片只交付静态站点。PHP 版本绑定、证书签发（ACME）与域名编辑是 M2 的后续片，
        对应能力位图里的 <code class="mp-code">php</code>（degraded）与
        <code class="mp-code">ssl</code>（unavailable）——在它们真的可用之前，这一页不会出现相应控件。
        新建站点的根目录是 0755 的空目录，放一个 <code class="mp-code">index.html</code> 就能访问。
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
