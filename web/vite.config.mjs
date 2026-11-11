// Vite 配置 —— 两个不显眼但必须成立的条件（改之前先读 internal/api/server.go 的 entranceGate）：
//
// 1. 产物必须是**单个 index.html**，不能拆出 /assets/*.js。
//    面板的安全入口是一条随机路径（panel.entrance），闸门对"入口之外、且没有会话"的
//    请求一律回伪装响应。带哈希的静态资源如果住在 /assets/，未登录时它们就在入口之外，
//    登录页会拿到一个伪装成 404 的 <script>。把它内联进 HTML，资源就永远和 HTML 同路径。
// 2. 输出目录是 ../webui/dist，由 webui/embed.go 的 //go:embed all:dist 打进二进制。
//    因此 dist 入库，`make build` 仍然不需要 npm；只有改前端时才需要 `make web`。
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import Components from "unplugin-vue-components/vite";
import { ElementPlusResolver } from "unplugin-vue-components/resolvers";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  plugins: [
    vue(),
    // 按需引入 Element Plus：只用得到的组件，避免整库进 HTML。
    Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: "css" })] }),
    viteSingleFile(),
  ],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    outDir: "../webui/dist",
    emptyOutDir: true,
    // 单文件产物里不存在"再请求一次"的余地，因此不做代码分割。
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    reportCompressedSize: false,
  },
});
