import { createApp } from "vue";
import "element-plus/theme-chalk/dark/css-vars.css";
import App from "./App.vue";
import "./styles.css";

// 面板只有深色一套皮肤：审计、能力位图、口令闸门这些页在深夜的终端旁边看，
// 不提供"亮色模式"这条会让人误以为换了环境的路。
document.documentElement.classList.add("dark");

createApp(App).mount("#app");
