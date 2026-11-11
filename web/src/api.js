// 与面板接口对话的唯一出口。
//
// 三条必须照抄的后端事实（internal/api/server.go、internal/api/auth.go）：
//   1. 写操作必须带 X-Mini-CSRF，值等于浏览器手里那个 mp_csrf Cookie（双提交）。
//      缺了它后端直接 403，不是"失败"，所以这里自动补，不给页面留"忘了带"的可能。
//   2. 错误体的形状是 {error:{kind,message}}，kind 是事实（password_change_required /
//      csrf / not_found …）。页面按 kind 分流，不按 HTTP 状态码或中文文案猜。
//   3. 请求一律带同源 Cookie（credentials: same-origin），会话就在那儿。
const cookie = (name) => {
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : "";
};

export const csrfToken = () => cookie("mp_csrf");

export async function api(path, opts = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  if (opts.method && opts.method !== "GET") headers["X-Mini-CSRF"] = csrfToken();
  const r = await fetch(path, Object.assign({ credentials: "same-origin" }, opts, { headers }));
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* 非 JSON：伪装页、空响应都算 */ }
  if (!r.ok) {
    const err = (json && json.error) || {};
    const e = new Error(err.message || ("HTTP " + r.status + (text ? "： " + text.slice(0, 80) : "")));
    e.kind = err.kind || "";
    e.status = r.status;
    throw e;
  }
  return json;
}
