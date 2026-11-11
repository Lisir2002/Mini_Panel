<script setup>
import { onMounted, ref } from "vue";
import { api } from "../api";
import { durText, fmtTime, timeTitle, tzLabel } from "../fmt";

const PAGE = 30;
const rows = ref([]);
const total = ref(0);
const offset = ref(0);
const error = ref("");
const busy = ref(false);

// 只追加、无清空接口：页面上因此不放"清空"或"删除这条"这种按钮，
// 后端也确实没有那样的端点（接口面上不存在删除审计记录的入口）。
async function load(reset) {
  error.value = "";
  if (reset) { rows.value = []; offset.value = 0; }
  busy.value = true;
  try {
    const d = await api("/api/v1/audit?limit=" + PAGE + "&offset=" + offset.value);
    total.value = d.total;
    rows.value = rows.value.concat(d.items || []);
    offset.value += (d.items || []).length;
  } catch (e) { error.value = e.message; }
  finally { busy.value = false; }
}

onMounted(() => load(true));
</script>

<template>
  <div class="mp-card">
    <h3>审计日志 <span class="mp-muted" style="font-weight:400;font-size:12px">共 {{ total }} 条</span></h3>
    <p class="mp-note">只追加，无清空接口。参数中的口令类字段在入库前已做掩码，另存 <code class="mp-code">params_hash</code> 供对账。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-bottom:8px" />
    <table>
      <thead>
        <tr>
          <th>时间（{{ tzLabel() }}）</th><th>用户</th><th>来源 IP</th>
          <th>动作 / 对象</th><th>结果</th><th>耗时</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(it, i) in rows" :key="i">
          <td :title="timeTitle(it.at)">{{ fmtTime(it.at) }}</td>
          <td>{{ it.user || "—" }}</td>
          <td :title="it.ip + (it.geo ? ' · ' + it.geo : '')">{{ it.ip || "—" }}</td>
          <td>
            <code class="mp-code mp-clip" :title="[it.action, it.target, it.params_mask].filter(Boolean).join('  ')">{{ it.action || "—" }}</code>
            <span v-if="it.target && it.target !== it.action" class="mp-muted mp-clip" :title="it.target">{{ it.target }}</span>
            <span v-if="it.params_mask" class="mp-muted mp-clip" :title="it.params_mask">{{ it.params_mask }}</span>
          </td>
          <td>
            <span class="mp-tag" :class="it.result === 'ok' ? 'on' : 'off'" :title="it.error ? '错误：' + it.error : '结果：' + it.result">{{ it.result || "—" }}</span>
          </td>
          <td>{{ durText(it.duration_ms || 0) }}</td>
        </tr>
        <tr v-if="!rows.length"><td colspan="6" class="mp-muted">还没有写操作记录。</td></tr>
      </tbody>
    </table>
    <div class="mp-row" style="margin-top:10px">
      <el-button size="small" :disabled="rows.length >= total" :loading="busy" @click="load(false)">加载更多</el-button>
      <el-button size="small" text :loading="busy" @click="load(true)">重新读取</el-button>
    </div>
  </div>
</template>

<style scoped>
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--mp-line); vertical-align: top; }
thead th { color: var(--mp-muted); font-weight: 500; white-space: nowrap; }
tr:last-child th, tr:last-child td { border-bottom: 0; }
</style>
