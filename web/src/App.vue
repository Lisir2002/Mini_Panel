<script setup>
import { computed, markRaw, onMounted, ref } from "vue";
import { api } from "./api";
import { clearGate, notify, setGate, store } from "./store";
import { fmtUp, tzLabel } from "./fmt";
import LoginView from "./views/LoginView.vue";
import OverviewView from "./views/OverviewView.vue";
import SitesView from "./views/SitesView.vue";
import CapabilitiesView from "./views/CapabilitiesView.vue";
import SettingsView from "./views/SettingsView.vue";
import SessionsView from "./views/SessionsView.vue";
import LockoutView from "./views/LockoutView.vue";
import SecurityView from "./views/SecurityView.vue";
import AuditView from "./views/AuditView.vue";

// 页面清单就是这一份。每一项都对应接口面上真实存在的东西：
// 概览→/system/info，网站→/sites（M2 第三片，静态站点；能力不可用时只显示理由），
// 能力→/capabilities，设置→/settings，会话→/sessions，CLI 对照→/lockout-risks，
// 安全→/2fa/*+/password，审计→/audit。数据库/备份/终端等页面不在这里，
// 因为后端还没有那些端点（能力位图里带理由地灰着），不是"藏起来了"。
// markRaw 不是优化而是正确性：组件对象一旦被包成响应式，<component :is> 拿到的
// 就是 Ref 而不是组件，页面会安静地什么都不渲染。
const VIEWS = [
  { key: "overview", label: "概览", comp: markRaw(OverviewView) },
  { key: "sites", label: "网站", comp: markRaw(SitesView) },
  { key: "capabilities", label: "本机能力", comp: markRaw(CapabilitiesView) },
  { key: "settings", label: "面板设置", comp: markRaw(SettingsView) },
  { key: "sessions", label: "会话", comp: markRaw(SessionsView) },
  { key: "lockout", label: "CLI 对照", comp: markRaw(LockoutView) },
  { key: "security", label: "账号安全", comp: markRaw(SecurityView) },
  { key: "audit", label: "审计日志", comp: markRaw(AuditView) },
];

const current = computed(() => VIEWS.find((v) => v.key === store.view) || VIEWS[0]);
const bootError = ref("");
const busy = ref(false);

// 口令闸门期间只渲染改口令这一件事。依据是后端的 passwordGate 只放行
// /session、/password、/logout 三条路径，别处点什么都只会拿到 403——
// 把其它卡片留在页面上只会让人以为面板坏了。
const gateOpen = ref(false);

async function enterApp() {
  const s = await api("/api/v1/session");
  store.session = s;
  store.authed = true;
  if (s.must_change_pw || s.password_expired) {
    setGate(
      s.password_expired
        ? "口令已超过面板设定的有效期，必须先换成新口令；换完之前面板不响应其它请求。"
        : "该账号的口令不是本人设置的（来自 minipanel passwd 或初始化），必须先改成自己的口令。"
    );
    gateOpen.value = true;
    return;
  }
  clearGate();
  gateOpen.value = false;
  store.caps = await api("/api/v1/capabilities");
}

async function boot() {
  bootError.value = "";
  try {
    store.health = await api("/healthz");
  } catch (e) {
    bootError.value = "无法连接面板接口：/healthz 没有响应，面板进程可能没起来。";
    return;
  }
  // 已有会话就直接进去，不让已经登录的人再输一次口令。
  try {
    await enterApp();
  } catch {
    store.authed = false;
  }
}

async function refresh() {
  busy.value = true;
  try {
    store.caps = await api("/api/v1/capabilities");
    // 换口令之后闸门可能已经解除，交给 enterApp 重新判定，前端不自己猜。
    await enterApp();
  } catch (e) {
    bootError.value = e.message;
  } finally {
    busy.value = false;
  }
}

async function logout() {
  try { await api("/api/v1/logout", { method: "POST" }); } catch { /* 已经没了就当成功 */ }
  store.authed = false;
  store.session = null;
  clearGate();
  notify("");
  await boot();
}

onMounted(boot);
</script>

<template>
  <div class="mp-wrap">
    <div class="mp-top">
      <div class="mp-brand">
        Mini Panel
        <small v-if="store.health">
          v{{ store.health.version }} · 面板已运行 {{ fmtUp(store.health.uptime_seconds || 0) }} · 浏览器时区 {{ tzLabel() }}
        </small>
      </div>
      <div class="mp-row" v-if="store.authed">
        <span class="mp-muted">{{ store.session?.username }}</span>
        <el-button size="small" :loading="busy" @click="refresh">刷新</el-button>
        <el-button size="small" text @click="logout">退出登录</el-button>
      </div>
    </div>

    <div v-if="bootError" class="mp-notice">{{ bootError }}</div>
    <div v-if="store.notice" class="mp-notice">
      {{ store.notice }}
      <el-button link size="small" @click="notify('')">收起</el-button>
    </div>

    <LoginView v-if="!store.authed" @done="boot" />

    <template v-else>
      <div v-if="store.gated" class="mp-gate-notice">{{ store.gateWhy }}</div>
      <nav v-else class="mp-card" style="padding:6px 10px;margin-bottom:14px">
        <el-menu mode="horizontal" :default-active="store.view" :ellipsis="false" @select="(k) => (store.view = k)">
          <el-menu-item v-for="v in VIEWS" :key="v.key" :index="v.key">{{ v.label }}</el-menu-item>
        </el-menu>
      </nav>
      <SecurityView v-if="store.gated" :open-password="gateOpen" @changed="enterApp" />
      <component v-else :is="current.comp" :key="current.key" />
    </template>
  </div>
</template>
