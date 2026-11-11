# Mini Panel 技术选型与 MVP 规格

> 本文件是**决策记录**，不是愿景清单。每一条结论都对应仓库里已经存在并能运行的代码；
> 与代码冲突时以代码为准，并请同时修订本文件。
>
> `internal/platform/capabilities.go:4` 的注释引用本文件的 **§2**（平台抽象层与能力位图契约），
> `Makefile` 的平台矩阵引用 **§6**。改动章节号时要把这两处引用一起改掉，否则注释就悬空了。

---

## §1 技术栈与选型理由

| 层 | 选择 | 理由（以及被否掉的方案） |
| --- | --- | --- |
| 语言 / 运行时 | Go，`go.mod` 的 `go` 指令为 **1.26.0** | 一个静态二进制覆盖 Linux/Windows/macOS/FreeBSD，目标机不装运行时。部署面板最怕的是"面板自己坏了没法修"，依赖越少越好。 |
| HTTP 路由 | `github.com/go-chi/chi/v5` | 纯路由 + 中间件，无框架绑架；`chi.Walk` 能被契约测试拿来枚举整张路由表（§3）。不需要 Gin 之类的重型依赖。 |
| 存储 | SQLite + `modernc.org/sqlite`（**纯 Go 驱动，无 cgo**） | 单写者工作负载，零外部数据库。选纯 Go 驱动是因为只要引入 cgo，交叉编译就要目标平台的工具链——这正是面板最难部署的地方。连接池固定 `SetMaxOpenConns(1)`（`internal/store/store.go:41`），顺手消掉了 HTTP handler 与调度器之间的 `database is locked` 竞争。 |
| 主机指标 | `github.com/shirou/gopsutil/v4` | cpu / mem / load / host 在四个平台上都已有实现，不必自己写 /proc 与 WMI 的两套。 |
| 口令哈希 | `golang.org/x/crypto/bcrypt` cost 12 | 成熟、无需自己调参。argon2id 也可，但 bcrypt 的 CPU/内存特性对这个场景够用，且不引入额外依赖。 |
| 终端口令输入 | `golang.org/x/term v0.48.0`（`go.mod:10`，唯一使用点 `cmd/minipanel/main.go:41`） | `minipanel passwd` 在 tty 下要**真的**关掉回显：只有 `term.ReadPassword` 会去改 termios 的 `ECHO` 位（`unix.Termios.Lflag`，底层是 `golang.org/x/sys`）。它是标准库同族的 `x/` 包——纯 syscall、无 cgo、唯一依赖是 `golang.org/x/sys v0.50.0`（本仓库已直接依赖，`go.mod:9`），复核：`cat "$(go env GOMODCACHE)/cache/download/golang.org/x/term/@v/v0.48.0.mod"`。用途只有一处（隐藏口令输入），不为它写平台代码；`x/term` 自身是跨平台的，因此不影响 §6 的交叉编译矩阵。 |
| 两步验证 | **手写 RFC 6238 TOTP**（`internal/sec/totp.go:12-83`，HMAC-SHA1 / 30 秒 / 6 位 / ±1 窗口） | 算法约 80 行，引入第三方库换来的只是把攻击面挪到依赖里。窗口容忍时钟漂移但拒绝空码。 |
| 面板证书 | 自签 ECDSA P-256，SAN 跟随本机地址（`internal/sec/tls.go`） | 面板自己只需要"不被中间人 + 不明文口令"，不需要公网信任链；站点证书是 M2 的事。 |
| 前端（当前态 M0） | **单文件手写静态页** `webui/dist/index.html`，零构建步骤 | `go build` 出来的二进制立刻可以在浏览器里验收整条安全链路；没有 node_modules、没有 lockfile 漂移、CI 只跑 Go。 |
| 前端（M1 起） | Vue 3 + Vite + Element Plus，`make web` 产出**单个** `webui/dist/index.html` | 站点/数据库/防火墙这些表格页需要真正的组件库。产物必须是单文件：安全入口之外的静态资源会被闸门伪装成 404，登录页会白屏（`TestUIBundleIsASingleSelfContainedFile`）。接口面不因换代而放宽，M0 的契约用例一条不许变红。 |
| 打包 | `//go:embed all:dist`（`webui/embed.go:15`） | 没有 nginx vhost、没有静态根目录、没有"运行时得存在某个路径"。 |

### 1.1 直接依赖清单（与 `go.mod:5-12` 逐条对应，共 6 个）

| 模块 | 版本 | 用在哪 | 许可证族 |
| --- | --- | --- | --- |
| `github.com/go-chi/chi/v5` | v5.5.0 | `internal/api` 的路由与中间件 | MIT |
| `github.com/shirou/gopsutil/v4` | v4.26.10 | `/api/v1/system/info` 的 cpu/mem/load/host | BSD-3 |
| `golang.org/x/crypto` | v0.58.0 | `internal/sec` 的 bcrypt / HMAC-SHA1，以及 `internal/acme` 的 RFC 8555 客户端（`acme` 子包） | BSD-3 |
| `golang.org/x/sys` | v0.50.0 | `internal/platform/platform_windows.go:10-11`（只在 `//go:build windows` 里） | BSD-3 |
| `golang.org/x/term` | v0.48.0 | `cmd/minipanel/main.go:41`，仅为 `passwd` 的隐藏输入 | BSD-3 |
| `modernc.org/sqlite` | v1.62.0 | `internal/store/store.go` 的 SQLite 驱动（纯 Go，无 cgo） | BSD-3 |

* 六项都带 `LICENSE` 文件（复核：`head -3 "$(go env GOMODCACHE)/modernc.org/sqlite@v1.62.0/LICENSE"`），
  全部是宽松许可（MIT / BSD-3-Clause），与本项目自身的 **GPL-3.0-only** 兼容；
  反向不成立：从这些依赖里抄代码可以，把 GPL-3.0 的 Mini Panel 链接进非兼容许可的发行物不行。
* 间接依赖全部来自以上六项（`go.mod:14-30`，15 个），没有单独的"工具依赖"分区。
* `x/` 三项与标准库同族：无 cgo、无生成代码、按 Go 发布节奏跟版本，因此把它们当作"标准库的
  延长线"来评估，不视为引入新框架。
* 复核：`sed -n '5,12p' go.mod` 应当列出上表 6 项；`grep -c '// indirect' go.mod` 应当是 **15**；
  新增依赖只出现在预期位置：`grep -rn "golang.org/x/term" --include='*.go' .` 只有一处 import
  （`cmd/minipanel/main.go:41`）。`go mod tidy -diff` 无输出（`go list -m all` 会把 `std` 与
  toolchain 自己也算进去，所以它不适合当"第三方数量"来引用）。

**不做的事**：不嵌 Python/php venv，不依赖系统 nginx 提供 UI，不引入 ORM/迁移框架（schema 版本化
自己实现，见 `internal/store/store.go:68-89`），不引入第三方 2FA / 遥测 SDK。ACME 用
`golang.org/x/crypto/acme`（RFC 8555 客户端，已在本仓库的 `x/crypto` 直接依赖里），
不额外引入 ACME SDK；DNS-01 与 EAB 没做，见 `docs/功能设计.md` §5.4。

---

## §2 平台抽象层与能力位图契约

**设计规则：UI 只根据能力位图渲染，别的一概不信。**
一个能力在当前平台不存在，就必须以"能力缺失 + 人类可读理由"的形式报出来；**绝不允许渲染一个
点了不会动的控件**，也不允许整块藏掉功能。

### 2.1 分层

* `internal/platform`（`paths.go:10-25`）定义 `Platform` 接口：`ID()`、`Detect()`、
  `ConfigDir()`、`DataDir()`、`LogDir()`、`SiteRoot()`、`BackupRoot()`。
  M2/M3/M4 的写操作接口（`WebServerCtl`、`FirewallCtl`、`PHPCtl`、`ServiceManager`）**现在就声明**，
  这样到里程碑时不需要重新塑形核心层。M2 第一片之后它们的现状不再相同：`PHPCtl` 在 Linux 上
  **已经是实现**（`internal/platform/platform_linux.go:30` 的 `var _ PHPCtl = linuxPlatform{}`，
  方法体在 `:68`、`:73`、`:75`，底下是 `internal/php` 的现场探测），
  `WebServerCtl`、`FirewallCtl`、`ServiceManager` 仍然只有类型定义、没有实现、没有路由。
  "有没有实现"这件事由编译器管：那句 `var _ PHPCtl = linuxPlatform{}` 一改签名就编不过。
  接口声明见 `internal/platform/paths.go:77`——那里同时写明 `PoolDir`/`SocketPath` 给的是
  **目标路径**，"这个名字上此刻有没有东西、内核里有没有人在听"是
  `internal/php/php.go:270 DirStatus()` / `:286 SocketStatus()` 的另一次读，不是这个接口的方法
  （M2 第二片把两次读分开，但没有改接口形状）。
* `internal/php` 是 M2 新增的一个小包：它只做一件事——把"这台机器上有哪些能跑的 PHP 版本、
  每个版本的 SAPI/pool/socket 路径在哪"从文件系统证据里读出来（`internal/php/php.go:119 DiscoverIn()`），
  不写任何东西、不装任何东西。`internal/platform` 依赖它，而不是反过来。
  第六片只加了一个纯函数 `internal/php/php.go:352 FPMVersions()`：从探测结果里筛出带 fpm 的
  版本，作为 `php_fpm_versions` 与页面选择器的唯一来源。站点版本绑定在平台层
  （`internal/platform/platform_linux.go:237 resolvePHPBinding()`）先按现场探测确认版本确有
  fpm，再把 socket 交给 `internal/nginx` 写进 vhost；**不创建 per-site pool**。
  第七片没有扩大 `SiteManager`，而是新增可选的
  `internal/platform/sites.go:103 SiteSettingsManager`（`SetBasics`），由
  `internal/platform/platform_linux.go:178` 接线到 nginx 的 `SetBasics`。这样旧 Provider 不必
  实现一个它做不到的写入口，页面也能从缺失的接口得出"本机不能编辑站点"，而不是画一个点了
  没反应的按钮。第八片同样走可选接口：`internal/platform/sites.go:121 SiteRewriteManager`
  （`SetRewrite` / `RewritePresets`），由 `internal/platform/platform_linux.go:189` / `:200`
  接线；模板集本身在 `internal/nginx/rewrite.go:54 RewritePresets()`，是编译进二进制的封闭
  词汇表，列表也由后端返回，页面不硬编码，因而不会与白名单漂移。第九片沿用同一模式：
  `internal/platform/sites.go:131 SiteProxyManager`（`SetProxy`），由
  `internal/platform/platform_linux.go:214` 接线到 `internal/nginx/proxy.go:177 SetProxy()`；
  反向代理的输入是一个经 `normalizeProxy`（`internal/nginx/proxy.go:138`）校验并规范化的 URL
  与一个 WebSocket 布尔值，指令由 `proxyLocationBody`（`internal/nginx/proxy.go:157`）
  固定生成；Provider 不实现该接口时端点返回 403 `capability` 并带上同一句理由，不假装
  写入路径存在。第十片同样新增可选接口
  `internal/platform/sites.go:139 SiteRedirectManager`（`SetRedirect`），由
  `internal/platform/platform_linux.go:225` 接线到 `internal/nginx/redirect.go:56 SetRedirect()`；
  跳转与反向代理共用 `parseUpstreamURL`（`internal/nginx/proxy.go:54`）做 URL 校验，
  指令由 `redirectLocationBody`（`internal/nginx/redirect.go:45`）固定生成。这样
  `location /` 的三种所有者（伪静态模板、反向代理、整站跳转）各自都有明确的写入接口，
  任何一边缺失都不会让页面凭空多出一个按钮。
* `internal/acme` 是 M2 第五片新增的包：它只负责一件事——用 `golang.org/x/crypto/acme`
  走完 RFC 8555 的 HTTP-01 签发（`internal/acme/acme.go:125 Issue()`），并把 token 写进
  调用方给的 webroot。它不知道 nginx、不知道站点、不碰面板配置；证书装进 vhost 由
  `internal/nginx` 的 `SetACMECertificate` 完成，平台层只做接线。账号密钥路径由调用方给，
  默认在 `/etc/minipanel/acme/account.key`（0600、父目录 0700）。
  `/proc`、`/etc/nginx`、SQLite 都不在这个包里出现——这是它能被 Pebble 单独集成测试的原因。
* 平台差异通过 **构建标签**分文件选择，而不是运行期判断：
  `platform_linux.go`（`//go:build linux`）、`platform_windows.go`（`//go:build windows`）、
  `platform_other.go`（`//go:build !linux && !windows`）。
  **`internal/*` 里除 `internal/platform` 自身外不允许出现 `runtime.GOOS` 分支**；复核命令：
  `grep -rn "runtime.GOOS" --include='*.go' . | grep -v internal/platform` 应当只剩注释。
* 值对象集中在 `capabilities.go`：`ReloadMode`（`sighup` / `restart_only` / `none`）、
  `PHPRuntimeMode`（`fpm` / `cgi` / `module` / `not_found`）、`ExtensionInstallMode`
  （`package` / `source` / `prebuilt_dll`）、`SchedulerKind`、`FirewallBackend`、`RemoteAccess`。
  这些枚举是前后端共同的词汇表，前端不需要知道 Go 的类型名。

### 2.2 诚实性规则（由测试强制，不靠自觉）

每一项功能在位图里是 `Feature{State, Reason, FixAction, Verify}`；`State != available` 时
`Reason` **必须**非空，写空串会被 `internal/platform/capabilities.go:193 set()` 就地换成
`noReasonStored`（`internal/platform/capabilities.go:193`），于是这条规则在测试里必然露馅。

* `newBase()`（`internal/platform/detect.go:18-76`）先把每一项功能置为 `unavailable` 并填好具体理由，
  平台实现再对它**当场验证过的**部分调用 `Allow()`，或调用 `Degrade()` 说清"主路径能做、缺的是哪一半"。
  默认拒绝，而不是默认允许。
  **实际状态**：`Allow()` 在生产代码里有五处——`internal/platform/detect.go:75` 点亮任何主机都成立的
  `audit`，`internal/platform/platform_linux.go:476` / `:477` / `:483` 在"nginx 可识别、进程是 root、
  `SiteACMEManager` 可用"时点亮 `site` / `site_write` / `ssl`，`:580` 在探测到带 fpm 的 PHP 版本
  且站点可写时点亮 `php_version_switch`。生产代码里的 `Degrade()` 有四处：
  `platform_linux.go:472` / `:473`（nginx 在但不是 root）与 `:564` / `:574`（PHP 有运行时但缺后端 /
  `php` 主路径仍缺安装卸载）。因此 `available` 不是只有 `audit`：`site`、`site_write`、`ssl`、
  `php_version_switch` 会在条件成立的主机上进入这一档；`php`、`database`、`firewall` 等仍停在
  `degraded` / `unavailable`。
  探测到的其它**事实**（有 ufw、有 sshd、有 PHP 8.3）只写进 `Capabilities` 的描述字段，
  不写成"功能可用"。
* `Deny()` / `Degrade()` / `Allow()` 三个入口都走同一个 `set()`：`Allow` 会清掉旧理由与
  fix/verify，`Deny` 与 `Degrade` 对未知 feature 名不 panic
  （`internal/platform/capabilities.go:207 Deny()` / `:213 Degrade()` / `:225 Allow()`）。
  `Has()` 只认 `available`，`degraded` 一律算不可用（`internal/platform/capabilities.go:186 Has()`），
  所以"M2 把 php 报成 degraded"不会让任何一道按 `Has()` 把关的接口放行。
* 五条测试：`TestDetectedCapabilitiesAreExplained`、`TestCapabilityStatesAreSymmetric`
  （`internal/platform/capabilities_test.go`），从 HTTP 外面重复断言的
  `TestCapabilitiesAreSelfConsistent`（`internal/api/m0_test.go`），PHP 的
  `TestDetectPHPFromRootedHosts` 与 M2 第二片的 `TestPHPCtlPathsAreTargetsAndStatesAreReads`
  （都在 `internal/platform/platform_php_test.go`，后者钉的是"`PHPCtl` 给的目标不随目录增删而变，
  变的是另一次读"）。入口是 `make check-honesty`。
* 第一条测试里除了"关了必须有理由"，还有一张**白名单**：
  `internal/platform/capabilities_test.go:179 implemented := map[string]bool{FeatAudit: true}` 是
  **无条件白名单**（只有 `audit` 在任何主机上都算已交付）；`site` / `site_write` / `ssl` 走
  `:220 siteWriterReady()` / `:234 siteTLSReady()` / `:251 phpSwitchReady()` 的**条件白名单**，谓词直接问平台实现
  "此刻有没有可写的 nginx / 有没有 ACME / 有没有带 fpm 的 PHP"，随后双向断言（`:188-198` 白名单外报 `available` 报错；
  `:205-211` 条件成立却没报成 `available` 也报错）。
  这一条把纪律从"不许没有理由"升级成"当前版本只许这些项是功能"——任何
  "探测到机制就 `Allow` 成功能"的写法，包括只在某一个平台上成立的写法，都会让测试变红。
  条件白名单只由 `Detect()` 的现场证据决定，所以同一份二进制在没装 nginx 的机器上
  `site` / `ssl` 仍是 `unavailable`，在只实现了手工证书的构建里 `ssl` 也到不了 `available`。
* 理由文案有下限："未实现"不算理由，必须写清**随哪个里程碑/Provider 交付**。
  同一种关闭状态在不同机器上要说不同的话：Linux 上"没装 ufw/firewalld/nft"与"装了但写入
  Provider 还没上"是两句不同理由（`platform_linux.go:500-506`），运维必须能分清是机器的问题
  还是面板版本的问题。

### 2.3 Windows 的差异（不是"以后再说"，是现在就写进位图）

| 差异 | 事实 | 位图表达 |
| --- | --- | --- |
| PHP 运行模型 | 官方构建没有 `php-fpm`，只有 `php.exe` / `php-cgi.exe` | `PHPModes = [cgi]`，并 `Deny("php_fpm", …)`；进程池管理标记 M2 |
| PHP 扩展 | 不能在被管理机上编译，工具链必须与上游构建完全一致 | `PHPExtInstall = [prebuilt_dll]`，理由写明需匹配 PHP 版本 × TS/NTS × VC 运行库 × 位数，并 `Deny(FeatPHPSourceExt, …)` |
| 服务管理 | 走 SCM，不是 systemd | `ServiceManager = windows_scm` |
| 防火墙 | WFP 恒在，但 `netsh` 写入 Provider 未交付 | `Firewall = windows_filter_platform` + `Deny(FeatFirewall, "…M4 交付（当前版本只读展示）")` |
| 计划任务 | `schtasks` | `Schedulers` 追加 `taskschd`；亚秒级任务只能靠面板自带调度器 |
| 重载方式 | nginx/Windows 没有 POSIX 信号的优雅重载 | `ReloadMode = restart_only` |
| 文件权限 | 没有 POSIX 位，只有 ACL 与继承 | `Permissions = acl`，`Deny(FeatFilePerms, …)`——chmod 类控件干脆不该出现 |
| 特权判定 | 问进程令牌，而不是往 HKLM 写一次试试 | `IsPrivileged = token.IsElevated()` |
| 远程访问 | RDP，OpenSSH 为可选组件 | `RemoteAccess` 相应填充 |

上表每一项都能在 `internal/platform/platform_windows.go:45-101 Detect()` 里逐行读到，
`SchedulerKind`/`FirewallBackend` 等枚举在 `internal/platform/capabilities.go:20-27`（ReloadMode）、`:41-46`（PHPRuntimeMode）、
`:51-58`（ExtensionInstallMode）、`:63-67`（SchedulerKind）、`:72-78`（FirewallBackend）、`:83-87`（RemoteAccess）。
**这些差异从 M0 就写进位图，不是"以后再说"**；而"在 Windows 上把它做完并支持"是
`M5 —— Windows 完整支持`，验收定义见 `docs/里程碑.md` 的 M5 一节。

### 2.4 其它平台

`platform_other.go`（macOS / *BSD）**只用于开发调试**：面板能起、API 能服务、能力位图能报，
但不实现也不声称任何主机管理 Provider（`site` 在那里被明确拒绝为"本平台仅用于开发调试"）。
`IsPrivileged` 在这些平台上保持 `false`——那个值描述的是进程，不是一个可被执行的能力。

### 2.5 前后端约定

前端拿到 `/api/v1/capabilities` 后只有三种合法渲染：可用控件、灰控件 + 理由、不出现该入口。
新增功能时必须同时新增 feature 名与（如需要）读写分离的子 feature（`site_write`、
`php_version_switch`、`firewall_write`、`service_write`），让"能看"与"能改"是两个不同的灰度。
反过来的禁令同样成立：**前端不许用 try/catch 假装某功能存在**。

---

## §3 OpenAPI 契约与契约测试

* 规格：`internal/api/openapi/panel.yaml`（OpenAPI 3.0.3）。安全语义直接写在描述里：伪装响应、
  双提交 CSRF、TLS fail-closed 都在规格中可见，评审接口面时不必先读 Go。
* 路由表：`internal/api/server.go` 的 `routes()`。
* `TestOpenAPIContractMatchesRoutes`（`internal/api/contract_test.go:23-66`）用 `chi.Walk` 枚举
  真实路由，与从 YAML 解析出的 `METHOD /path` 集合**双向**比对：注册了却没登记 → 失败；
  登记了却不存在 → 失败。
* `internal/api/contract_test.go:70 TestSpecDeclaresTheSecurityContract` 钉住规格里的安全词汇
  （`name: mp_session`、`name: X-Mini-CSRF`、`panel.ip_allowlist`、`panel.unauth_status`），
  并扫描规格，出现 `mod_name` / `class` / `{module}` / `{action}` 这类反射式片段直接失败；
  路径参数按**名字白名单**放行，白名单是 `{key, id, name}`：`key` 是 M0 的设置项枚举，
  `id` 是 M1 会话页加的 `sessions.ref`（先过 `^[0-9a-f]{16}$` 再作为绑定参数进 SQL），
  `name` 从 M2 第三片起用于 `/api/v1/sites/{name}...`，由 `internal/nginx.ValidateName`
  统一校验字符集与长度（同一函数也用在写文件前），未知名字返回 404 而不是 500。
  动词、模块名、方法名进 URL 是反射式接口的起点，这条白名单就是拦这个的。
* YAML 解析是**逐行的**，不是引入 YAML 库：这个文件的版式由我们自己生成、由本测试守护，
  为此拖一个依赖进测试路径不划算。因此改 YAML 时保持缩进约定（`paths:` 在 0 列，路径 2 列，
  HTTP 方法 4 列），否则测试会以"规格描述了不存在的接口"的形式报出来。
* 入口是 `make check-contract`。

作用：把"文档会不会过期"从人工纪律变成构建失败。接口一旦要加，必须同时给出规格，
而给出规格就意味着有人（或 AI）读过安全语义并把它写进 `description`。

---

## §4 配置与存储的分界

一句话：**`panel.json` 放"数据库还没通就必须知道的引导值"，SQLite 放"运行态"。**

### 4.1 panel.json

字段（`internal/config/config.go:21-32`，共 10 个，不多不少）：
`bind`、`port`、`entrance`、`tls`、`hosts`、`data_dir`、`log_dir`、`session_ttl`、
`login_limit`、`unauth_status`。默认值 `0.0.0.0:29080`、`tls=true`、`session_ttl=12h`、
`login_limit=5`、`unauth_status=404`、入口为空（`config.go:63-73`）。

* **权限 0600**，写入走 `panel.json.tmp` + `rename` 原子替换（`config.go:96-109`），测试断言
  文件模式与"不留残料"（`config_test.go:52-81`）。入口路径本身就是伪装的一部分，世界可读的
  配置文件等于把伪装送给同机上的任何账号；`.gitignore` 也把 `panel.json` 排除在外。
* `Duration` 自定义类型同时接受 `"12h"` 与纳秒整数，非法字符串**报错而不是静默变 0**
  （`config.go:36-59`），防的是"手改的 12h 被当成 12 纳秒 → 会话瞬间过期"这类静默失控。
* `Validate()`（`config.go:111-133`）分两类：
  *硬失败*——端口越界、bind 为空、`unauth_status` 不在 {400,401,403,404,444}、`data_dir` 为空；
  *软修复*——`session_ttl < 1m` 回到 12h、`login_limit <= 0` 回到 5。笔误不该把面板锁死。
* 只有 `minipanel init`（以及首次 `serve` 的内联初始化）有权写这些值。

### 4.2 SQLite

`users` / `sessions` / `login_events` / `audit` / `settings` / `schema_meta`，全部由版本化
迁移建立（`internal/store/store.go:87-181`）。`schema_meta.version` 比二进制新就**拒绝降级启动**
（`:74-75`），避免旧二进制把新库改坏。

* 建库与 `-wal`/`-shm` 一律 chmod 0600（`internal/store/store.go:53-61`）——sqlite 默认跟着 umask 走，而这里面是
  口令哈希、会话 ID 和审计记录。
* `settings` 是**带类型、有校验的一行一项**，取代"用某个 `.pl` 文件存不存在来表达开关"。
  那种写法会出现"文件是 0 字节空文件、读出来算开启、UI 显示关闭"的自相矛盾状态，是这个项目
  明确不复制的（`store.go:1-7`）。
* 设置写路径是显式白名单（`internal/api/system.go:78-83`）：
  `panel.ip_allowlist`（只接受 IP 与 CIDR，**拒绝域名**——放行域名等于把访问判定交给一个
  面板不控制的 DNS）、`panel.password_expiry_days`（0-3650）、`panel.basic_auth`、
  `panel.trust_proxy`。其余键一律 `400 immutable`。
* 引导值在 `settings` 列表里也有行，但**值与来源都从进程现读**：`internal/api/system.go:108`
  命中 `runtimeSetting()`（`:126`）就把 `value` 换成进程真正在用的值，并把 `source` 标成
  `panel.json`（`:114`），没命中的运行态可写项才是 `db`（`:107`）。因此
  **SQLite 里的 `panel.port` 只是初始化镜像，不是第二真源**（种子行见
  `internal/store/store.go:160`）——照镜像显示等于在设置页上显示一个根本没在监听的端口。
* `panel.entrance` 的 `source` 是 `panel.json`，但**值永远不是入口路径本身**：开着的时候显示
  "已启用（值不在此展示，见 panel.json 或 minipanel doctor）"，关闭的时候显示"已关闭"
  （`internal/api/system.go:132-138`）。理由写在注释里：入口是伪装手段，而设置页是最容易被
  截图的地方。要看真值请用 `minipanel doctor`。这条由 `TestSettingsAllowListAndValidation`
  （`internal/api/m0_test.go:372`）断言，同一条测试还要求 `panel.port` 等于进程实际监听端口。

### 4.3 一致性

`panel.entrance` 同时写进 `settings` 表，是为了让 UI 有一个地方看到"入口开着还是关着"，
但**真值只有 panel.json 一份**：启动与 `reset-entrance` 都会把配置文件的值刷进行里
（`cmd/minipanel/main.go` 的 `initialize()` / `cmdResetEntrance()`），不制造第二真相源；
读的时候再按 §4.2 用进程值覆盖一次。

---

## §5 安全模型

（面向实现的摘要；行为叙述与"为什么"见 `README.md` 的安全模型一节。）

1. **凭据传输 fail-closed**：`credentialsAllowed()` = TLS 生效，或 bind 与客户端**都是**回环
   （`internal/api/auth.go:51-55`）。不满足时 `login`/`setup` 返回 `503 tls_required`。
   没有"公钥拿不到就发明文"的客户端降级路径。
2. **会话**：`mp_session` HttpOnly + SameSite=Strict + Secure（TLS 时），TTL 取
   `panel.session_ttl`；登录成功即种，登出与改密即作废（改密保留当前会话，其余全部
   `revoked=1`）。口令由 CLI 设置时作废该用户**全部**会话。
3. **CSRF**：双提交 `mp_csrf` ↔ `X-Mini-CSRF`，常量时间比较，只作用于非幂等方法。
4. **登录失败锁定**：`ip|username` 维度，达到 `login_limit` 后按窗口翻倍退避、封顶 1 小时；
   锁定期内正确口令也拒绝。计数在内存，事件在 `login_events`。
5. **安全入口是未认证探测的伪装，不是鉴权层**：未登录时入口外的路径一律按 `unauth_status`
   应答（含 444 断连）；盲 POST `/login`/`/setup` 因缺少 `mp_entrance` 标记同样按伪装处理；
   `/healthz` 永远可达。**持有合法 `mp_session` 后任何路径都可访问**——这是有意的：SPA 的导航、
   刷新与深链必须落在原路径上，把它们全部改写到一个魔法路径会拿可用的界面换一个勾。
   因此**入口不能缓解 XSS，也不能缓解 Cookie 泄露**，任何"安全入口保护登录后的面板"的表述都是
   错的；`entranceGate` 的注释（`internal/api/server.go:194-212`）已经把这段结论写死，
   文档与 README 必须原样表达这条边界。**"登录后逐路径校验入口"是 M1 待办**（见
   `docs/里程碑.md`），在它实现之前不得写成现状。真正的访问控制 = 监听地址 + 会话令牌与有效期
   + `panel.ip_allowlist` + CSRF + 登录锁定。
   伪装响应的**形态**也是一条决定：中性 HTML 错误页，只含状态码文本，不含产品名与版本
   （`internal/api/server.go:285 disguise()` 的注释）。不用 Go 默认 `http.Error` 的
   `text/plain`，因为"404 Not Found"那 10 个字节本身就是运行环境指纹，而这条响应的目的正是
   让探测者学不到东西；也不冒充 nginx 的错误页——这个进程就是 web server，一张普通 404 是
   事实，冒充别人的错误页在事故响应时误导运维的程度不亚于误导扫描器。页面里内联
   `<link rel="icon" href="data:,">`，否则浏览器会二次请求 `/favicon.ico`，把一次探测变成两行日志。
6. **审计只追加**：包内无删除/清空方法，接口面无删除端点；写操作无论成败都记录；
   敏感形状参数掩码为 `***`，另存未掩码原值的 SHA-256 `params_hash` 供取证比对。
7. **无反射式接口**：一条路由一个处理函数，唯一路径参数是白名单化的 `settings/{key}`，由契约测试
   守住。口令类接口不接收 `mod`/`class`/`action` 之类的名字映射。
8. **口令策略不是开关**：长度 ≥10、四类中至少三类（`internal/sec/sec.go:55-79`），Web 与 CLI
   同一条规则，不可关闭；bcrypt cost 12。用户名格式同样强制（字母开头，3-32 位）。
9. **账号枚举防护**：未知用户与错误口令响应完全一致。
10. **无遥测**：非测试代码没有任何出站 HTTP/拨号；`/healthz` 的 `telemetry:false` 是事实陈述。
11. **HTTP 基线**：`nosniff` / `X-Frame-Options: DENY` / `no-referrer` / `no-store`，TLS 下加
    HSTS，`MinVersion: TLS1.2`；`X-Forwarded-For` 默认不信；请求体 1 MiB 上限、审计缓冲 8 KiB
    上限；无全局 `WriteTimeout`（为 M4 终端 WebSocket 留路），只设 header/idle 超时。

---

## §6 交叉编译与构建矩阵

`CGO_ENABLED=0` 是硬要求（§1 选择纯 Go SQLite 驱动的全部意义）。以下 8 个组合必须都能编过，
`make build-all` 就是这条矩阵；表里的 ✅ 表示"在这台开发机上 `make build-all` 实际产出了该文件"，
不是"在该平台上跑过"——运行验证是另一件事，里程碑里逐条写。

| GOOS | amd64 | arm64 |
| --- | --- | --- |
| linux | ✅ | ✅ |
| darwin | ✅ | ✅ |
| windows | ✅（`.exe`） | ✅（`.exe`） |
| freebsd | ✅ | ✅ |

* Windows 目标需要的 `golang.org/x/sys/windows` 与 `registry` 只在 `//go:build windows` 文件里
  引用，非 Windows 构建不会把它们拉进依赖图。
* 后加的 `golang.org/x/term`（§1.1）不影响这条矩阵：它自身跨平台、无 cgo，依赖只有 `x/sys`。
  加入该依赖之后，这台开发机上重新逐条实测 8 个组合（`make build-all`）仍然全部退出码 0，
  `CGO_ENABLED=0` 未变。
* 版本三元组 `Version`/`Commit`/`BuildDate` 位于 `internal/build/build.go:4-8`，
  由 `-ldflags -X` 注入；`make version` 验证。
* 产物落在 `bin/`，`.gitignore` 已覆盖 `bin/`、`*.exe` 以及开发运行目录 `data/`。
* 前端不参与交叉编译：`webui/dist/index.html` 是入库的静态文件，`go:embed` 在每个目标上都成立，
  所以 `make web` 只是存在性检查。
* 其中 **8 个组合（4 OS × 2 arch）在这台开发机上逐条实测过退出码 0**（`make build-all` 一次编出
  全部 8 个；本轮另外用 `CGO_ENABLED=0 GOOS=… GOARCH=… go build` 逐个复核，8/8 通过）。
  **重点目标是 linux/amd64、linux/arm64、darwin/arm64、windows/amd64、freebsd/amd64** 这 5 个——
  它们覆盖四个 OS 上实际部署最常见的架构，其余 3 个（darwin/amd64、windows/arm64、freebsd/arm64）
  同批产出但不在"要拿去装机"的清单里。另外 `GOOS=linux|windows|darwin|freebsd go vet ./internal/...`
  四个平台都退出码 0——**vet 能跨平台跑**意味着平台专属的接口误用（例如把 `syscall.SysProcAttr`
  写进公共代码）不会被留到发布日。复核：
  `for os in linux windows darwin freebsd; do GOOS=$os go vet ./internal/... || echo "$os FAIL"; done`

---

## §7 MVP 范围边界（明确不做什么）

* **不做多租户 SaaS 面板**：这是内部自用的运维工具，一台机器一个面板，管理员就是运维本人。
* **不在 M0 提供任何主机管理写操作**：能力位图里没有的功能，接口面上也不存在（不是"接口在但
  没实现"）。
* **不做遥测、不做云端账号、不做面板自更新**。
* **不通过 API 修改引导值**（端口 / 入口 / TLS / 会话时长）：改文件 + 重启。
* **不引入 cgo**，因此不引入任何需要目标平台工具链的依赖。
* **不在本仓库或文档里收录外部面板的研究材料、证据包、真实服务器地址或口令**。

里程碑验收标准见 `docs/里程碑.md`。

---

## §8 已知缺陷与不接受的做法

这一节是**负面清单**：已经踩过的坑与永不接受的设计。它存在的原因是——只写"我们做对了什么"的
文档会在下一次改动里被理所当然地推翻。

### 8.1 已经修掉的缺陷：SQLite 数据文件曾经是 0644

`internal/store.Open()` 早期直接按 SQLite 默认方式建库，而 sqlite 创建文件跟随进程 umask，
默认主机上是 022 → **`minipanel.db` 权限 0644，同机任何账号可读**。而这个文件里放着
bcrypt 口令哈希、有效会话 ID 和整份审计记录：会话 ID 泄露等于不需要口令的登录，本地提权或者
同机跑着别的客户项目时这是直接失守。

现在的做法（`internal/store/store.go:46-57`）：打开之后**主动 chmod 0600**，并且把 `-wal`
与 `-shm` 一起处理——checkpoint 之前这两个兄弟文件持有与主文件相同的字节，只收紧主文件等于
什么都没做；chmod 失败就 `db.Close()` 并返回错误，**不允许带着错误权限继续启动**。
代码这一侧是完整的：`TestFilePermissionsAreOwnerOnly` 断言的是**主文件**权限
（`internal/store/store_test.go`，只看 `minipanel.db`），`-wal`/`-shm` 的收紧目前**只有代码保证、
没有断言**；面板证书与私钥的 0600 同样没有专门测试（`internal/config/config.go:96-109` 的
`panel.json` 0600 是有断言的，见 `config_test.go:52-81`）。这几条缺口集中记在 §8.4，
不要读成"都有测试压着"。

接受的做法：权限由代码在创建时收紧，不依赖安装脚本、不依赖"运维记得 chmod"。
不接受的做法：把权限当成部署文档里的一行提示。

### 8.2 设计纪律：探测到机制 ≠ 拥有功能

看到 `ufw` 在 `/usr/sbin` 里，不代表面板会写防火墙规则；机器上有 `php8.1` 二进制，不代表面板
能切换版本；文件备份在 POSIX 上很简单，也**不代表备份按钮点得动**。ACME 是这条纪律的近期样本：
`golang.org/x/crypto/acme` 从 M0 就随 `x/crypto` 在依赖图里，但直到第五片把账号密钥、challenge
写入、nginx 安装与续期循环都接上，`ssl` 才允许 `available`——"依赖里有 ACME 客户端"本身不是能力。
"探测到机制就报成功能"产出的正是这个项目改写面板的初衷所要消灭的东西：一个看着能点、点了没
反应的按钮，或者一整块被藏起来的已交付功能。

因此这条纪律是**测试强制**的，不是文档口径（M2 第一片是它的正面样本：`internal/php` 当场探到
PHP 版本与 SAPI 之后，只改写 `php` 一项的状态与理由——`internal/platform/platform_linux.go:535`
起读现场，`:564` 报的是"检测到了什么、缺哪个后端"。第六片把"站点能绑定到某个已有版本"
交付了，`php_version_switch` 才允许在"站点可写 + 探测到 fpm"时 `available`；
但 `php` 本身仍是 `degraded`，多版本安装/卸载与 `php_ext_source` 没有写入路径）：

* `newBase()` 默认拒绝每一项功能并写好理由（`internal/platform/detect.go:18-76`，拒绝表 `:50`）；
* `TestDetectedCapabilitiesAreExplained`（`internal/platform/capabilities_test.go:110`）除了
  "关了必须有理由"，还有一张**白名单**：`capabilities_test.go:181` 的
  `implemented` 是无条件项（当前 `{FeatAudit: true}`），`:220`、`:234` 与 `:251` 的
  `siteWriterReady` / `siteTLSReady` / `phpSwitchReady` 是条件项（`site`、`site_write`、`ssl`、
  `php_version_switch`）。白名单外任何 `available` 都失败，条件成立却没报成 `available` 也失败。
  所以本版本的 `available` 可以是 `audit`，也可以是现场证明可写的 `site` / `site_write` /
  `ssl`，以及现场证明有 fpm 可绑的 `php_version_switch`；
  `php` 被报成 `degraded` 既不需要、也不允许动这张表。身份、会话、入口、CSRF、锁定、2FA、
  能力契约、自检 CLI 是**面板自身**已交付的部分，它们不在 `features` 名单里，也就不可能被探测
  "顺带"点亮；
* `TestCapabilitiesAreSelfConsistent`（`internal/api/m0_test.go`）从 HTTP 外面把同一条规则再打一遍，
  防止只有包内自测而接口面撒谎。

入口是 `make check-honesty`。要把某项功能加进白名单，唯一正确的顺序是：**先有跨平台可用的实现
与路由，再改白名单，最后改文档**——反过来就是超前承诺。

### 8.3 已修复的缺陷：入口字母表与自检断言互相矛盾（曾让 `make test` 约 1/5 概率飘红）

**这条已经从"未修的源码问题"变成"修好并把原因写进注释的历史"**。留着它是因为它演示了一个有用
的现象：**一个正确的断言连续飘红，通常不是测试坏了，而是生成器和它自己声明的规则不一致**。

* **当时的矛盾**：字母表里留着 `i`，而同包的 `TestEntranceShape`（`internal/sec/sec_test.go:75`，
  函数从 `:75` 开始）要求生成的入口不得出现 `"0o1liIO"` 这些"用手机键盘容易敲错的字符"，禁集
  **包含 `i`**。旧字母表 `abcdefghijkmnpqrstuvwxyz23456789` 是 32 个字符（只去了 `l`、`o`、`0`、`1`），
  于是 `NewEntrance()` 每个字符有 1/32 的概率取到 `i`，8 个字符里至少出现一个的概率
  `1-(31/32)^8 ≈ 22.4%`。当时的实测：分 3 批共 32 次
  `go test -count=1 -run TestEntranceShape ./internal/sec/` 红 7 次（21.9%，与理论值吻合），
  报错形如 `ambiguous character 'i' in entrance ...`；而全量 `make test` 常常是绿的——
  **"跑一次绿"从来不能证明随机缺陷不存在**。
* **修复方式**：改生成器，不改断言——把 `i` 从字母表里删掉。现在是 `internal/sec/sec.go:116` 的
  `abcdefghjkmnpqrstuvwxyz23456789`；`:108-115` 的注释把这次矛盾、为什么要排除易混字符、以及熵的
  算法都写在代码旁边：**23 个字母 + 8 个数字 = 31 个符号，8 字符 = `8·log2(31) ≈ 39.6` bit**。
  这两个数字可以独立复核：
  `python3 -c "a='abcdefghjkmnpqrstuvwxyz23456789'; import math; print(len(a), round(8*math.log2(len(a)),2))"`
  → `31 39.63`。注意 31 **不是** 2 的幂，所以"每字符恰好 5 bit"是错的（注释早期确实这么写，现已改对）；
  `rand.Int` 走拒绝采样，取模偏置也不存在。
* **为什么会飘红（结构性原因）**：字母表（生成侧）与 `"0o1liIO"`（断言侧）是两处独立文本，没有共同
  真源，各自演进就会再次打架。所以防回归的手段是**断言 + 重复次数**，注释本身不算防线。
* **现在的防回归与复核**（随机性缺陷必须用重复次数说话）：

```bash
go test -count=60  -run TestEntranceShape ./internal/sec/   # 本轮 ok：60 次独立生成，0 次易混字符
go test -count=200 -run TestEntranceShape ./internal/sec/   # 本轮 ok：200 次独立生成，0 次
```

  对照修复前：同一条命令 32 次里红 7 次。`-count=N` 就是最省事的回归口径，不需要额外脚本；CI 若想
  便宜一点，保留 `N=60` 也够——在旧状态下 60 次全绿的概率只有 `0.776^60 ≈ 0.2%`。
* **仍然没被覆盖的部分**：断言防的是"字母表加回易混字符"，禁集比字母表更宽是**正确**的设计。
  形状本身是断言过的——`sec_test.go:77` 要求 `/` 前缀且 `len(e) == 9`，把 `NewEntrance()` 里的
  8 改成 6 会立刻红。**没被断言的是字母表**：`entranceAlphabet` 在任何测试文件里一次都没出现
  （`grep -rn "entranceAlphabet" --include='*_test.go' .` 为空），所以"31 个符号、不含易混字形"
  这条规则只有 `:82` 的禁集在间接守着，往字母表里加回 `i` 只能靠概率撞上来才发现。这条记进 §8.4。
* 与 §8.1（数据文件权限）同类：缺陷应当由代码在创建时收紧，而不是靠文档提醒运维手抖。

### 8.4 测试缺口（诚实清单）

先说**已经补上的部分**（这不是缺口，写在这里是为了让 review 知道边界挪到哪了）：
`cmd/minipanel/main_test.go`（489 行、11 个用例）把整层 CLI 语义纳入 CI——`init` 的
`--bind/--port/--insecure-no-tls/--entrance` 真的落到 `panel.json`
（`main_test.go:45 TestInitHonoursItsFlags`，含 `panel.json` 0600 断言 `:72`）；未知 flag / 多余位置参数 /
未知子命令一律报错（`:77 TestInitRejectsUnknownAndExtraArgs`）；`--entrance -` 是关闭而不是"替我生成一个"
（`:90 TestInitEntranceFlag`）；`reset-entrance` 同步配置文件与 settings 镜像、且 `--set` 与
`--disable` 互斥（`:124 TestResetEntranceKeepsConfigAndMirrorInStep`）；`passwd` 置
`must_change_pw`，并拒绝弱口令 / 空输入 / 非法用户名 / 双用户名
（`cmd/minipanel/main_test.go:176 TestPasswdSetsMustChangeAndValidatesInput`）；`-h` 不算失败
（`:219 TestSubcommandHelpIsNotAFailure`）；usage 文本与子命令、flag 清单一致
（`:237 TestUsageCoversEveryCommand`）；banner 显示在用的端口与地址、入口关闭时写"未设置"
（`:257 TestBannerReportsLiveConfigValues`）。

M2 第二片补上了一条曾经记在本表里的缺口：**`doctor` 打印的 socket 路径没有校验是不是真的有人在听**。
现在 `internal/php/php.go:286 SocketStatus()` 读内核表 `/proc/net/unix` 判活
（解析在 `:323 listeningSocketPaths()`，`St` 列 `01` 才是 LISTEN，Path 是行尾整段而不是某个固定列），
`cmd/minipanel/php.go:30 phpProbe()` 把它和 `PHPCtl` 给的路径分开成两次读，`phpSummary()` 的句子
因此变成"路径来自 PHPCtl，状态是此刻现场读的"。压它的三条：`internal/php/php_test.go` 的
`TestStatesOfTheReportedPaths`（现场 bind 一个 unix socket、`SetUnlinkOnClose(false)` 后关闭，
得到"文件在但内核里没人听"这个真实形状）、`TestSocketStatusUsesThePathColumnVerbatim`（伪造内核表，
钉住列解析与"CONNECTED 不算在听"）、`cmd/minipanel/php_test.go` 的
`TestDoctorTellsStoppedFpmApartFromRunningFpm`（同一台假主机的两种内核状态，doctor 必须说出不同句子）。
本机没有跑着的 php-fpm，所以"listening / idle"两句话是在测试自己造的 listener 上验证的，不是实测报告；
本轮另外在一台 rooted 假主机上用 **python** 现场 bind 一个 unix socket 跑过一遍 `minipanel doctor`
（活着 → "内核里有进程在听"，`close()` 不 unlink → "文件在但内核里没人听，fpm 大概是停了"，两次都不出
"注意："），原始输出记在 README「如何验证」里。特意换 python 而不是 Go，是为了让这条判断不依赖某个
运行时的退出清理行为。

下面是**代码已经保证、测试还没断言**的部分。列出来是为了让人知道哪些地方要靠 review 兜住，
而不是假装"全都有测试压着"。

| 缺口 | 怎么确认它确实是缺口 | 现在靠什么保证 |
| --- | --- | --- |
| 面板自签证书生成、SAN 跟随本机地址重签 | `grep -rn "EnsureSelfSignedTLS" --include='*_test.go' .` 为空 | 代码 `internal/sec/tls.go:26`；`make doctor` 的证书行、`minipanel init` 的实际输出 |
| `-wal` / `-shm` 的 0600 | `TestFilePermissionsAreOwnerOnly` 只 `os.Stat` 主库文件 | 代码 `internal/store/store.go:46-57` 的三元素循环 |
| 面板证书与私钥的 0600 | `internal/sec` 只有一个测试文件且不碰证书 | 代码 `internal/sec/tls.go:74-86` |
| `444`（挂断型）伪装真的会断连 | `disguise()` 的 Hijacker 分支只在配置 444 时走到，M0 测试跑的是 404 | 代码 `internal/api/server.go:286` |
| ACME 只对 Pebble 跑过端到端，没有对 Let's Encrypt 生产环境真签过 | `grep -rn "pebble" --include='*_test.go' .` 只命中 `internal/acme/pebble_test.go`；它默认跳过（`pebble` 不在 PATH 时 `t.Skip`），CI 不会自动跑 | 协议流程由 `internal/acme` 的 9 个单元用例覆盖；端到端复核命令写在 README「如何验证」；生产签发仍受 80 端口可达与域名解析两个外部条件约束 |
| DNS-01 / 通配符签发没有实现，也没有测试 | `grep -rn "DNS01\|dns-01\|Wildcard" --include='*.go' internal/` 只应命中通配符拒绝逻辑，不应有 DNS 客户端 | 代码在写任何配置之前拒绝（`internal/acme/acme.go` 的 `normalizeDomains` + `internal/platform/platform_linux.go` 的 `obtainACME`），HTTP 返回 `422 acme_unsupported`；通配符站点只能上传证书 |
| 前端"灰 + 理由"的实际渲染 | 仓库里没有 UI 自动化：`make web` 编译前端并断言产物只有一个文件，`make check-ui` 断言能力 key 全覆盖与端点全覆盖，但**"页面画出来对不对"这一步仍然靠人**（真实浏览器的 puppeteer 脚本刻意不入仓库，它依赖本机 chrome） | `make check-ui` 的三条 + `make check-honesty` 保证理由必然存在；每轮里程碑手工跑一遍浏览器断言并在 README"如何验证"里记下条数 |
| `minipanel passwd` 的 **tty 分支**（真关回显那一条） | 测试文件自己写明 `go test` 下 stdin 不是 tty（`cmd/minipanel/main_test.go:212-213`），所以 `term.IsTerminal` 为真的分支走不到；管道分支与全部校验分支**已经**在 CI 里 | 代码 `cmd/minipanel/main.go:685`（`IsTerminal`）→ `:691`（`term.ReadPassword`）、`:700`（`readLine`）；本轮用 `pty.fork()` 手工验证主端流里不回声明文。这是 §8.2 那条纪律的反面教材：**文案说"不回显"而代码没关 ECHO** 曾经成立过，只有断言能防它回来；补法是在测试里自建 pty，或把该分支抽成可注入接口 |
| 入口字母表本身没有断言 | 形状是断言过的（`sec_test.go:77` 要求 `/` 前缀且 `len(e) == 9`，把 8 字符改短会红），但 `entranceAlphabet` 在测试里一次都没被引用（`grep -rn "entranceAlphabet" --include='*_test.go' .` 为空）：没人断言它是 31 个符号。往字母表里加回易混字符，只能靠 `:82` 那条禁集撞上来才发现 | 禁集断言 + §8.3 的 `-count=200` 重复；注释 `internal/sec/sec.go:108-115` 写明了 31 符号 × 8 字符 ≈ 39.6 bit |
| PHP 探测只认 Debian/Ubuntu 的布局 | `grep -rn remi internal/php/` 为空——`/etc/php/<版本>` + `/usr/{,s}bin` 之外的形状（RPM 系、remi/SCL 的 `/etc/opt/remi/php83`）没有任何 fixture 覆盖 | 代码 `internal/php/php.go:110-118` 的注释把这个假设写明了；找不到就报"未检测到"，而不是猜一个路径出来。M2 第二片给它加了一个**被动探测器**：`cmd/minipanel/php.go:124 phpBitmapMismatch()` 第四条规则——`PHPCtl` 报的 socket 在内核里是 LISTEN、而位图 `php_modes` 里没有 fpm，这两件事只可能来自两边看的不是同一处，于是 doctor 打一行"注意："点名"非 Debian 布局"。它不能修好探测，但能让这种机器上的错法从"静默 502"变成"自检先说出来"；正解仍然是补一组 redhat 形状的假 root，而不是往探测里塞 if |
| socket 判活只说"有人在听"，不说听的**是不是 php-fpm**，也没做过一次 FastCGI 握手 | `grep -rn "net\.Dial\|fcgi" internal/php/ cmd/minipanel/php.go` 为空（本轮实测无输出）：`SocketStatus` 唯一的信息源是内核按路径记的账，路径背后是什么进程它不知道 | 代码 `internal/php/php.go:292 socketStatus()` 只在 `St` 列为 `01` 时报 listening；表读不到时返回 `unknown` 而不是猜"没人听"（`internal/php/php_test.go:448` 断言这条），文案对应 `cmd/minipanel/php.go:79 socketWords()` 里那句"读不到 /proc/net/unix，判断不了"。"这个后端真的能执行 PHP 吗"要等 M2 的站点写入侧发一次 FastCGI 请求才算验证过 |
| `MINI_PANEL_DEBUG=1` 目前没有可观察效果 | `newLogger()`（`cmd/minipanel/main.go:165`）会降到 Debug 级，但 `grep -rn "\.Debug(" --include='*.go' internal cmd \| grep -v _test` 为空 | 它只是留口。`README.md` 快速上手一节已按"今天不会多出任何输出"来写，等真出现 Debug 埋点这条缺口自动消失 |

补齐建议按价值排序：证书生成与 SAN 重签 → 444 分支 → passwd 的 pty 分支 → `-wal`/`-shm` 权限断言。
这几条都可以只在 `internal/sec`、`internal/api`、`internal/store`、`cmd/minipanel` 内部加测试，
不动接口面，也不动能力位图白名单。

### 8.5 其它不接受的做法（同源于上面的教训）

* 不接受"用文件存不存在表达开关"：见 §4.2，空文件读出来算开启、UI 显示关闭这类自相矛盾状态
  一律由带类型、有校验的一行取代。
* 不接受把引导值做成 API 可写字段：见 `README.md` 安全模型第 6 条与 §5；被盗用的会话不该能把
  面板从运维脚下搬走。
* 不接受"前端自己判断能力"：前端只照抄 `features` / `unavailable`，判断权在服务端与测试（§2.5）。
* 不接受把伪装写成鉴权：见 §5 第 5 条。

### 8.6 已修复的缺陷：`init` 收下 flag 却一个都不生效，banner 还装作照办

`cmd/minipanel/main_test.go:19-26` 的文件头注释把这条写死在代码旁边：**"HTTP 测试永远看不见的
缺陷"**——`minipanel init --port 29095 --bind 127.0.0.1` 会正常解析 flag、然后照常写入默认值，
再打印一个看起来已经采纳了请求的 banner。它和 §8.1（权限靠运维记得 chmod）、§8.3（文案说
"不回显"而代码没关 ECHO）是同一个家族的第三种表现：

1. **声明与实现分离**：flag 表、提示语、banner 都是"声明"，`config.Save` 的字节才是"实现"。
   只看输出的人会以为它成功了。
2. **失败是静默的**：解析成功 ≠ 生效；没有报错、没有退出码变化，所以人工试一遍也发现不了
   ——只有把值**从盘上读回来**才能区分。
3. **它的爆炸半径比看起来大**：入口、端口、TLS 开关都是引导值，"以为关了 TLS"或"以为换了端口"
   直接决定这台机器暴露什么。

现在的防回归方式（不是注释，是断言）：

* `cmd/minipanel/main_test.go:45 TestInitHonoursItsFlags` 逐个读回 `cfg.Port` / `cfg.Bind` / `cfg.TLS`，
  错误信息写得很直白："a silently dropped flag is worse than no flag at all"（`:53`）；
  并断言 `panel.json` 落盘 0600（`:72`，理由：这个文件里放着入口和 TLS 开关）。
* `cmd/minipanel/main_test.go:77 TestInitRejectsUnknownAndExtraArgs` 堵掉"多写了 flag/参数但被忽略"的另一半：
  `--bogus`、多余位置参数、未知子命令三种都必须返回错误。
* `cmd/minipanel/main_test.go:257 TestBannerReportsLiveConfigValues` 要求 banner 里的端口/地址/URL 与配置一致，
  绑定回环时**禁止**出现 `0.0.0.0`，入口关闭必须显示"未设置"而不是空白——banner 是操作者唯一
  一眼扫过的东西，它不能是第二真源。
* `cmd/minipanel/main_test.go:36-44 readBack()` 刻意用 `serve` 同一个 `config.Load` 路径读，这样"写进去但读不出来"
  也算失败。

**这条给后续里程碑留下的规矩**：任何新增 flag / 设置项 / 引导值，验收方式是"从盘上读回来 +
从 UI 侧再读一次"，而不是"命令没报错"。同理，`doctor` 与 banner 的输出必须是**进程真实使用的值**
（§4.3 的镜像覆盖规则），否则它们会变成新的第二真源。
