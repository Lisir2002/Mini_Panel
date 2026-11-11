import { reactive } from "vue";

// 全站共享的一小块状态。刻意不做 Store 框架：面板的"事实"全在接口里，
// 前端只缓存这一次会话内读到的东西，刷新即重取，不存在前端自己推断的状态。
export const store = reactive({
  health: null,      // GET /healthz
  session: null,     // GET /api/v1/session
  caps: null,        // GET /api/v1/capabilities
  authed: false,     // 有没有合法会话
  gated: false,      // 口令闸门：只放行 /session、/password、/logout
  gateWhy: "",       // 闸门理由，取自接口，不由前端编
  view: "overview",  // 当前页
  notice: "",        // 顶部一次性提示
});

export function notify(text) { store.notice = text || ""; }

export function setGate(why) {
  store.gated = true;
  store.gateWhy = why || "该账号必须先修改口令。";
}

export function clearGate() {
  store.gated = false;
  store.gateWhy = "";
}
