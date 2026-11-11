<script setup>
import { onMounted, ref } from "vue";
import { api } from "../api";
import { store } from "../store";

const props = defineProps({ openPassword: { type: Boolean, default: false } });
const emit = defineEmits(["changed"]);

const error = ref("");
const msg = ref("");
const secret = ref("");
const url = ref("");
const totpOpen = ref(false);
const totpConfirm = ref("");
const pwOpen = ref(props.openPassword);
const pwOld = ref("");
const pwNew = ref("");
const busy = ref(false);

// 两步验证的"生成密钥"和"生效"是两步：扫码后必须回提一次 6 位口令，
// 未确认前不改变登录流程。这条纪律在后端（handleTOTPSetup / handleTOTPEnable），
// 页面只是不给人跳过它的机会。
async function setup2fa() {
  error.value = ""; msg.value = "";
  try {
    const d = await api("/api/v1/2fa/setup", { method: "POST" });
    secret.value = d.secret; url.value = d.url; totpOpen.value = true; msg.value = d.note || "";
  } catch (e) { error.value = e.message; }
}

async function enable2fa() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    await api("/api/v1/2fa/enable", { method: "POST", body: JSON.stringify({ code: totpConfirm.value }) });
    msg.value = "两步验证已启用，下次登录需要动态口令。";
    totpOpen.value = false; totpConfirm.value = "";
  } catch (e) { error.value = e.message; }
  finally { busy.value = false; }
}

async function changePw() {
  error.value = ""; msg.value = ""; busy.value = true;
  try {
    await api("/api/v1/password", { method: "POST", body: JSON.stringify({ old_password: pwOld.value, new_password: pwNew.value }) });
    msg.value = "口令已更新，该账号的其它会话已全部作废（当前这条仍在用）。";
    pwOld.value = ""; pwNew.value = "";
    // 改密成功是口令闸门唯一的出口：闸门是否解除由接口重新判定，
    // 而不是前端自己认为解开了。
    emit("changed");
  } catch (e) {
    error.value = e.message;
    if (e.kind === "password_change_required") store.gateWhy = e.message;
  }
  finally { busy.value = false; }
}

onMounted(() => { if (store.session?.totp_enabled) msg.value = "两步验证已启用。"; });
</script>

<template>
  <div class="mp-card">
    <h3>账号安全</h3>
    <p class="mp-note" v-if="!store.gated">
      「配置两步验证」先生成密钥，扫码后必须输入 6 位口令确认才真正生效，未确认前不改变登录流程；
      「修改口令」校验当前口令，成功后该账号的<b>其它</b>会话全部作废（当前会话仍可继续使用，
      要结束它就再去「会话」页撤销本条或直接退出登录）。
    </p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" style="margin-bottom:8px" />
    <el-alert v-if="msg" :title="msg" type="success" :closable="false" style="margin-bottom:8px" />

    <div class="mp-row" v-if="!store.gated">
      <el-button @click="setup2fa">配置两步验证</el-button>
    </div>

    <div v-if="totpOpen" class="mp-row" style="flex-direction:column;align-items:stretch;margin-top:10px">
      <div class="mp-muted mp-tiny">密钥（Base32）：<code class="mp-code">{{ secret }}</code></div>
      <div class="mp-muted mp-tiny" style="word-break:break-all">otpauth：<code class="mp-code">{{ url }}</code></div>
      <div class="mp-row" style="margin-top:6px">
        <el-input v-model="totpConfirm" placeholder="扫码后输入 6 位口令以启用" maxlength="6" style="max-width:240px" />
        <el-button type="primary" :loading="busy" @click="enable2fa">确认启用</el-button>
      </div>
    </div>

    <div class="mp-row" style="margin-top:12px">
      <el-button v-if="!store.gated" @click="pwOpen = !pwOpen">修改口令</el-button>
    </div>

    <div v-if="pwOpen" style="max-width:420px;margin-top:10px">
      <el-form label-position="top" @submit.prevent="changePw">
        <el-form-item label="当前口令">
          <el-input v-model="pwOld" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新口令（≥10 位，四类字符中至少三类）">
          <el-input v-model="pwNew" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-button type="primary" native-type="submit" :loading="busy">提交</el-button>
      </el-form>
    </div>

    <div class="mp-hint" v-if="store.gated">
      这一页现在是面板唯一可用的部分：口令闸门只放行 <code class="mp-code">/session</code>、
      <code class="mp-code">/password</code>、<code class="mp-code">/logout</code> 三条路径，
      换完口令之前点别处只会得到 403。
    </div>
  </div>
</template>
