<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { fmtTime, timeTitle, tzLabel } from "../fmt";

// 会话列表是 M1 把"谁在用我的登录态"从一张没人读的表变成一页的原因。
// 两条必须照抄的后端语义（internal/api/sessions.go 的包注释、openapi/panel.yaml）：
//   * 行上的 id 是 sessions.ref（8 随机字节的十六进制），不是会话令牌。
//     mp_session 的值在任何响应、审计与日志里都不出现——它拿着就能登录。
//   * 已撤销的行仍然返回："哪个是家里的笔记本"这个问题需要历史，
//     一个每次刷新都在缩短的表格答不了。
const data = ref(null);
const error = ref("");
const msg = ref("");
const busy = ref(false);

// 接口把顺序给成"还活着的在前、时间倒序"（规格里写明的口径），
// 前端按同一口径排，不依赖返回顺序恰好如此。
const dead = (r) => (r.revoked || r.expired ? 1 : 0);
const rows = computed(() => {
  const it = (data.value?.items || []).slice();
  it.sort((a, b) => dead(a) - dead(b) || b.created_at - a.created_at);
  return it;
});

const liveText = computed(() => {
  if (!data.value) return "";
  return "当前 " + data.value.live + " 条在用 · 共 " + data.value.total + " 条记录（含已撤销）";
});

async function load() {
  error.value = "";
  try { data.value = await api("/api/v1/sessions"); }
  catch (e) { error.value = e.message; }
}

async function revoke(row) {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const r = await api("/api/v1/sessions/" + encodeURIComponent(row.id), { method: "DELETE" });
    if (r && r.need_relogin) {
      // 撤销的就是自己这一条：服务端已经清掉会话 Cookie，浏览器继续拿着它
      // 只会在下一个请求上多挨一次 404，所以这里立刻回到登录门禁。
      location.reload();
      return;
    }
    msg.value = "已撤销 1 条会话。";
    await load();
  } catch (e) { error.value = e.message; await load(); }
  finally { busy.value = false; }
}

async function revokeOthers() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    const r = await api("/api/v1/sessions", { method: "DELETE" });
    // 自己的会话故意保留：这条操作的语义是"把别的浏览器踢掉"，
    // 做完不该被自己的按钮赶出去——结束当前会话的正确出口是「退出登录」。
    msg.value = "已撤销 " + (r?.revoked ?? 0) + " 条其它会话" + (r?.kept_current ? "，当前这条仍在用。" : "。");
    await load();
  } catch (e) { error.value = e.message; }
  finally { busy.value = false; }
}

onMounted(load);
</script>

<template>
  <div class="mp-card">
    <h3>会话</h3>
    <p class="mp-note">
      谁在用什么地方登录着这个账号。「撤销其它全部」不会结束你当前这条会话；
      要结束当前会话请用右上角的「退出登录」。
    </p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-bottom:8px" />
    <el-alert v-if="msg" :title="msg" type="success" :closable="false" style="margin-bottom:8px" />

    <div class="mp-row" style="margin-bottom:10px">
      <el-button size="small" :loading="busy" @click="load">刷新</el-button>
      <el-popconfirm
        title="撤销除本条以外的全部会话？"
        confirm-button-text="确认撤销"
        cancel-button-text="取消"
        confirm-button-type="danger"
        width="260"
        @confirm="revokeOthers"
      >
        <template #reference>
          <el-button size="small" type="danger" plain :disabled="!rows.some((r) => !r.current && !r.revoked && !r.expired)">
            撤销其它全部
          </el-button>
        </template>
      </el-popconfirm>
      <span class="mp-muted mp-tiny">{{ liveText }}</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>来源 IP</th><th>客户端</th><th>建立时间（{{ tzLabel() }}）</th>
          <th>到期</th><th>状态</th><th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rows" :key="r.id">
          <td><code class="mp-code">{{ r.ip || "—" }}</code></td>
          <td>
            <span class="mp-clip" :title="r.user_agent">{{ r.user_agent || "（未提供）" }}</span>
          </td>
          <td :title="timeTitle(r.created_at)">{{ fmtTime(r.created_at) }}</td>
          <td :title="timeTitle(r.expires_at)">{{ fmtTime(r.expires_at) }}</td>
          <td>
            <span class="mp-tag on" v-if="r.current">当前会话</span>
            <span class="mp-tag off" v-else-if="r.revoked">已撤销</span>
            <span class="mp-tag off" v-else-if="r.expired">已过期</span>
            <span class="mp-tag flat" v-else>在用</span>
          </td>
          <td style="width:120px">
            <el-popconfirm
              v-if="!r.revoked && !r.expired"
              :title="r.current ? '撤销你自己正在用的这条？你会立刻退回登录页。' : '撤销这条会话？'"
              confirm-button-text="确认撤销"
              cancel-button-text="取消"
              confirm-button-type="danger"
              width="280"
              @confirm="revoke(r)"
            >
              <template #reference>
                <el-button size="small" text type="danger">撤销</el-button>
              </template>
            </el-popconfirm>
            <span v-else class="mp-muted mp-tiny">—</span>
          </td>
        </tr>
        <tr v-if="!rows.length"><td colspan="6" class="mp-muted">没有会话记录。</td></tr>
      </tbody>
    </table>

    <div class="mp-hint">
      表里的会话标识是后端给的<b>公开句柄</b>（<code class="mp-code">sessions.ref</code>，16 位十六进制），
      只用于定位这一行；真正的会话令牌 <code class="mp-code">mp_session</code> 不会出现在页面、接口响应、
      审计条目或日志的任何一处，因为它拿着就能登录。不存在、已撤销、属于别的账号——三种情况后端回同一个
      404，这个页面因此也不会成为"哪些会话曾经存在"的探测器。
    </div>
  </div>
</template>

<style scoped>
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--mp-line); vertical-align: top; }
thead th { color: var(--mp-muted); font-weight: 500; white-space: nowrap; }
tr:last-child th, tr:last-child td { border-bottom: 0; }
</style>
