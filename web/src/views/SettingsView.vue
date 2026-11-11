<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api";
import { fmtDur, fmtTime, timeTitle, tzLabel } from "../fmt";

// 显示层换算，不改数据：布尔串→是/否、秒数→可读时长、epoch→时刻，原始值一律留在 title。
// 依据是后端自身的语义（internal/api/system.go 的 runtimeSetting / validateBoolString /
// validateNonNegativeInt 与 store.go 的种子值）。panel.port 一类启动项后端已经回填
// 进程真正在用的值，前端不做任何数字猜测。
const SEC_KEYS = { "panel.session_timeout": true };
const UNIT_KEYS = { "panel.login_limit": " 次", "panel.password_expiry_days": " 天" };
const isNum = (v) => /^\d+$/.test(v);

const items = ref([]);
const error = ref("");
const saved = ref("");
const key = ref("");
const val = ref("");
const busy = ref(false);

const editable = computed(() => items.value.filter((i) => i.editable));

// source 是接口给的事实（"db" | "panel.json"），不是前端推断：panel.json 意味着这一行
// 回显的是进程当前实际在用的引导值，拿数据库镜像冒充就会自相矛盾。
function src(it) {
  const raw = it.source == null ? "" : String(it.source);
  if (raw === "panel.json") {
    return { text: "运行中 panel.json", cls: "info", title: "source=panel.json：改它要动配置文件并重启" };
  }
  if (raw === "db") return { text: "数据库", cls: "flat", title: "source=db：值取自 settings 表" };
  return { text: raw || "（接口未给出 source，请报告缺陷）", cls: "off", title: "接口原样返回的 source：" + raw };
}

function shown(it) {
  const v = it.value == null ? "" : String(it.value);
  if (v === "") return { text: "（未设置）", title: "原始值：空字符串" };
  if (v === "true" || v === "false") return { text: v === "true" ? "是" : "否", title: "原始值：" + v };
  if (SEC_KEYS[it.key] && isNum(v)) return { text: fmtDur(+v) + "（" + v + " 秒）", title: "原始值（秒）：" + v };
  if (UNIT_KEYS[it.key] && isNum(v)) return { text: v + UNIT_KEYS[it.key], title: "原始值：" + v };
  if (it.key === "panel.unauth_status" && isNum(v)) {
    return { text: v, title: "原始值：" + v + "（未认证请求得到的伪装响应状态码）" };
  }
  if (/_at$/.test(it.key) && isNum(v) && v.length >= 10) {
    return { text: fmtTime(+v), title: "原始值（epoch 秒）：" + v + " · " + tzLabel() };
  }
  return { text: v, title: "原始值：" + v, pre: v.indexOf("\n") >= 0 };
}

async function load() {
  try {
    const d = await api("/api/v1/settings");
    items.value = d.items || [];
    if (!key.value && editable.value.length) key.value = editable.value[0].key;
  } catch (e) { error.value = e.message; }
}

async function save() {
  error.value = ""; saved.value = ""; busy.value = true;
  try {
    await api("/api/v1/settings/" + encodeURIComponent(key.value), { method: "PUT", body: JSON.stringify({ value: val.value }) });
    saved.value = "已保存 " + key.value;
    await load();
  } catch (e) { error.value = e.message; }
  finally { busy.value = false; }
}

onMounted(load);
</script>

<template>
  <div class="mp-card">
    <h3>面板设置</h3>
    <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-bottom:8px" />
    <el-alert v-if="saved" :title="saved" type="success" :closable="false" style="margin-bottom:8px" />
    <table>
      <thead>
        <tr><th>键</th><th>值</th><th>更新时间（{{ tzLabel() }}）</th><th>来源</th><th>可改性</th></tr>
      </thead>
      <tbody>
        <tr v-for="it in items" :key="it.key">
          <th><code class="mp-code">{{ it.key }}</code></th>
          <td :title="shown(it).title" :style="shown(it).pre ? 'white-space:pre-wrap' : ''">{{ shown(it).text }}</td>
          <td :title="timeTitle(it.updated_at)">{{ fmtTime(it.updated_at) }}</td>
          <td :title="src(it).title"><span class="mp-tag" :class="src(it).cls">{{ src(it).text }}</span></td>
          <td>
            <span class="mp-tag partial" v-if="it.editable">可改</span>
            <span class="mp-tag off" v-else>需改配置文件并重启</span>
          </td>
        </tr>
      </tbody>
    </table>
    <div class="mp-row" style="margin-top:12px">
      <el-select v-model="key" style="max-width:280px" :disabled="!editable.length">
        <el-option v-for="it in editable" :key="it.key" :label="it.key" :value="it.key" />
      </el-select>
      <el-input v-model="val" style="flex:1" :placeholder="editable.length ? '新值' : '当前没有可通过接口修改的设置项'" :disabled="!editable.length" />
      <el-button type="primary" :disabled="!editable.length" :loading="busy" @click="save">保存</el-button>
    </div>
    <div class="mp-hint">
      "来源"列照抄接口的 source 字段：<b>运行中 panel.json</b> 表示这一行回显的是进程当前实际在用的引导值
      （端口、TLS、会话超时、登录失败上限、未认证状态码），数据库里的镜像不会拿来冒充；<b>数据库</b> 表示值取自 settings 表。
      安全入口的展示文案由后端决定，面板页不会把入口路径本身画出来——要看入口请在服务器上执行
      <code class="mp-code">minipanel doctor</code>。
    </div>
  </div>
</template>

<style scoped>
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--mp-line); vertical-align: top; }
thead th { color: var(--mp-muted); font-weight: 500; }
tbody th { color: var(--mp-muted); font-weight: 500; width: 22%; }
tr:last-child th, tr:last-child td { border-bottom: 0; }
</style>
