<script setup>
import { computed, ref } from "vue";
import { api } from "../api";
import { store } from "../store";

const emit = defineEmits(["done"]);

const health = computed(() => store.health || {});
const isSetup = computed(() => !!health.value.requires_setup);

const username = ref("");
const password = ref("");
const code = ref("");
const showTotp = ref(false);
const error = ref("");
const busy = ref(false);

// 入口提示只说真实状态：忘记入口或口令的出口是服务器上的 CLI，
// 页面上不放任何"找回密码"的假入口（面板没有邮件通道）。
const hint = computed(() =>
  isSetup.value
    ? "仅在没有账号时可用；也可在服务器上执行 minipanel passwd <用户> 创建。"
    : health.value.entrance_enabled
      ? "安全入口已启用：只有从入口路径进来的请求才允许提交口令。忘记入口或口令时，在服务器上执行 minipanel doctor / minipanel passwd <用户>。"
      : "未启用安全入口（panel.json 里 entrance 为空）：任何路径都会打开这个登录页。"
);

async function submit() {
  error.value = "";
  busy.value = true;
  const body = { username: username.value, password: password.value };
  if (showTotp.value) body.code = code.value;
  try {
    if (isSetup.value) {
      await api("/api/v1/setup", { method: "POST", body: JSON.stringify(body) });
      // 初始化只建账号，登录仍然是独立一步——两条路径的后端语义不同，不合并。
      await api("/api/v1/login", { method: "POST", body: JSON.stringify(body) });
    } else {
      const r = await api("/api/v1/login", { method: "POST", body: JSON.stringify(body) });
      if (r && r.totp_required) {
        showTotp.value = true;
        error.value = "需要动态口令。";
        busy.value = false;
        return;
      }
    }
    emit("done");
  } catch (e) {
    // 后端用 kind/文案区分"口令不对"和"还差一个 6 位码"，前者不该把验证码框弹出来。
    if (/动态口令/.test(e.message || "")) showTotp.value = true;
    error.value = e.message;
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="mp-card" style="max-width:420px">
    <h3>{{ isSetup ? "初始化：创建第一个管理员" : "登录" }}</h3>
    <form autocomplete="off" @submit.prevent="submit">
      <el-form-item label="用户名">
        <el-input v-model="username" autocomplete="username" />
      </el-form-item>
      <el-form-item label="密码">
        <el-input v-model="password" type="password" show-password autocomplete="current-password" />
      </el-form-item>
      <el-form-item v-if="showTotp" label="动态口令（6 位）">
        <el-input v-model="code" inputmode="numeric" maxlength="6" />
      </el-form-item>
      <el-button type="primary" native-type="submit" :loading="busy">
        {{ isSetup ? "创建并登录" : "登录" }}
      </el-button>
    </form>
    <div class="mp-hint">{{ hint }}</div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-top:10px" />
  </div>
</template>
