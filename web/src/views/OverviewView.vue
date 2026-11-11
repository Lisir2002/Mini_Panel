<script setup>
import { onMounted, ref } from "vue";
import { api } from "../api";
import { fmtDur, fmtTime, gb } from "../fmt";

const info = ref(null);
const error = ref("");

onMounted(async () => {
  try { info.value = await api("/api/v1/system/info"); }
  catch (e) { error.value = e.message; }
});

// 标签必须区分"宿主机运行时长"与"面板进程运行时长"：前者在 system/info，
// 后者在 /healthz，混成一格就会有人说"面板重启过机器也重启过"。
const kpis = (d) => [
  { t: "系统", v: d.os_pretty || d.os || "—" },
  { t: "内核", v: d.kernel || "—" },
  { t: "架构", v: d.arch || "—" },
  { t: "CPU", v: (d.cpu_cores || "—") + " 核" },
  { t: "内存", v: d.memory ? gb(d.memory.total) : "—", s: d.memory ? "已用 " + d.memory.usedPercent.toFixed(1) + "%" : "" },
  { t: "负载", v: d.load ? d.load.m1.toFixed(2) : "—", s: d.load ? "5m " + d.load.m5.toFixed(2) + " · 15m " + d.load.m15.toFixed(2) : "" },
  { t: "系统已运行", v: d.uptime_seconds ? fmtDur(d.uptime_seconds) : "—", s: d.boot_time ? "上次启动：" + fmtTime(d.boot_time) : "" },
  { t: "面板端口", v: String(d.panel ? d.panel.port : "—"), s: d.panel && d.panel.tls ? "HTTPS" : "HTTP" },
];
</script>

<template>
  <div class="mp-card">
    <h3>概览</h3>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <template v-else-if="info">
      <div class="mp-kpis">
        <div v-for="k in kpis(info)" :key="k.t" class="mp-kpi">
          <span>{{ k.t }}</span>
          <b :title="k.v">{{ k.v }}</b>
          <span v-if="k.s">{{ k.s }}</span>
        </div>
      </div>
      <div class="mp-hint">
        站点根目录 {{ info.panel?.siteRoot || "未设置" }} · 数据目录 {{ info.panel?.dataDir || "—" }}。
        这一页只有读侧：概览不放任何破坏性动作，资源时间序列与监听清单在 M4（监控）交付之前不会出现。
      </div>
    </template>
    <el-skeleton v-else :rows="3" animated />
  </div>
</template>
