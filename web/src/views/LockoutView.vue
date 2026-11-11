<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";

// 「CLI 对照」是 M1 的最后一页，也是唯一一页内容不由前端自己编的页面：
// 表体来自 GET /api/v1/lockout-risks，而那个端点和 `minipanel doctor` 调的是同一个函数
// （internal/lockout.Risks）。这一点是这页存在的理由——如果页面从 /settings + /session
// 自己拼一份说法，面板就有了两套「你会不会被关在外面」的答案，而它们一定会漂开。
//
// 页面只读，而且不是一句免责声明：本面板没有任何能执行命令的端点，
// undo 那列的文本只能由人 SSH 到机器上自己敲。响应里的 executable=false 就是这条契约。
const data = ref(null);
const error = ref("");

async function load() {
  error.value = "";
  try { data.value = await api("/api/v1/lockout-risks"); }
  catch (e) { error.value = e.message; }
}

// 后端已经按 §6.3 的顺序把行排好了（入口→口令→监听→证书→会话→2FA→IP→有效期→待确认），
// 前端不再重排：这个顺序本身就是「从最容易把自己关在外面的一项开始」。
const rows = computed(() => data.value?.items || []);

const summary = computed(() => {
  if (!data.value) return "";
  const n = data.value.total ?? rows.value.length;
  const a = data.value.armed ?? 0;
  if (a === 0) return "全表 " + n + " 项，当前没有一项处于能把人关在外面的状态。";
  return "全表 " + n + " 项，其中 " + a + " 项当前能把人关在外面；doctor 只列这几项，这一页列全部。";
});

onMounted(load);
</script>

<template>
  <div class="mp-card">
    <h3>CLI 对照（自救对称表）</h3>
    <p class="mp-note">
      面板这边每一个能把人关在外面的开关，都对应一条在服务器本机执行的
      <code class="mp-code">minipanel</code> 命令。这一页只读：它不执行、不代表面板能执行，
      列出的命令只能 SSH 到机器上自己敲——面板故意没有"替你跑一条命令"的接口。
    </p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-bottom:8px" />
    <div class="mp-row" style="margin-bottom:10px">
      <el-button size="small" @click="load">刷新</el-button>
      <span class="mp-muted mp-tiny">{{ summary }}</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>开关</th><th>能不能把你关在外面</th><th>现在的状态</th><th>在本机上怎么解开</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in rows" :key="r.name">
          <td>{{ r.name }}</td>
          <td>
            <span class="mp-tag off" v-if="r.armed">当前能</span>
            <span class="mp-tag flat" v-else>当前不能</span>
          </td>
          <td>{{ r.state }}</td>
          <td><code class="mp-code">{{ r.undo }}</code></td>
        </tr>
        <tr v-if="!rows.length && !error"><td colspan="4" class="mp-muted">后端没有返回任何行。</td></tr>
      </tbody>
    </table>

    <div class="mp-hint">
      三条口径上的事，写在这里而不是每条行话里：<b>入口路径的值本身不在这一页出现</b>——它和会话令牌
      一样是 secret，面板只在响应里说"已启用"；<b>"现在是不是正被失败锁定挡住"读不到</b>——那个计数器只在
      面板进程的内存里，重启即清，所以这一行说的是规则而不是当前状态；<b>口令强度没有开关可关</b>，
      忘了口令的唯一出口是 <code class="mp-code">minipanel passwd</code>。同一张表由
      <code class="mp-code">minipanel doctor</code> 打印它的"当前是"部分，两处不可能各说一套。
    </div>
  </div>
</template>

<style scoped>
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--mp-line); vertical-align: top; }
thead th { color: var(--mp-muted); font-weight: 500; white-space: nowrap; }
tr:last-child th, tr:last-child td { border-bottom: 0; }
.mp-code { white-space: pre-wrap; word-break: break-all; }
</style>
