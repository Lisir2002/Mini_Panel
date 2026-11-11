// 时间/时长的展示层换算。输入一律是接口给的 epoch 秒或时长秒，
// 面板不做任何数值猜测，也不用 locale 相关的 toLocaleString（同一份产物要在
// 不同机器的浏览器里给出可对照的读数）。
const pad = (n) => String(n).padStart(2, "0");

export function tzLabel() {
  const o = -new Date().getTimezoneOffset();
  const sign = o < 0 ? "-" : "+";
  const a = Math.abs(o);
  return "UTC" + sign + Math.floor(a / 60) + (a % 60 ? ":" + pad(a % 60) : "");
}

export function fmtTime(sec) {
  if (!sec) return "—";
  const d = new Date(sec * 1000);
  return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
    pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}

// 人类可读时长。小于 1 分钟也要说清楚（旧 fmtUp 在这一档返回空字符串）。
export function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec) || 0);
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const p = [];
  if (d) p.push(d + " 天");
  if (h) p.push(h + " 小时");
  if (m && d < 1) p.push(m + " 分钟");
  if (!d && !h && (s || !p.length)) p.push(s + " 秒");
  return p.join(" ") || "0 秒";
}

export const fmtUp = fmtDur;

// 时刻的完整含义放在 title 里：正文是本地时刻，副信息是时区与原始 epoch，
// 这样两个人对着屏幕争执"到底几点"时有原始数字可看。
export function timeTitle(sec) {
  if (!sec) return "—";
  return fmtTime(sec) + " " + tzLabel() + "（epoch " + sec + "）";
}

export const durText = (ms) => (ms >= 1000 ? (ms / 1000).toFixed(1) + " 秒" : ms + " 毫秒");

export const gb = (n) => (n / 1e9).toFixed(1) + " GB";
