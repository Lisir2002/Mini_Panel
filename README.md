# Mini Panel

自主可控的云服务器管理面板。**内部自用优先**：目标是一台机器上跑一个静态二进制，把
站点、PHP、数据库、防火墙、备份这些日常操作收在一个网页里，并且每一次点击都留痕。

Mini Panel 模仿的是宝塔面板的**使用习惯**（面板端口 + 安全入口 + 站点列表 + 一键申请证书
这套工作流，以及 `bt` 那样的命令行自救入口），**不是抄它的代码**：本仓库没有任何一行来自
第三方面板，全部实现都是 Go 标准库 + 少量上游库（直接依赖共 6 个，逐条清单见
`docs/技术选型与MVP规格.md` §1）。

**授权：GPL-3.0-only 完全开源**（见 `LICENSE`）。依赖侧 chi 为 MIT，gopsutil、
x/{crypto,sys,term}、modernc.org/sqlite 为 BSD-3-Clause，均与 GPL-3.0 兼容。
变更授权需要全部贡献者同意，因此这条在 M0 定稿后不再轻动。

仓库地址：https://github.com/Lisir2002/Mini_Panel

---

## 当前状态：M0 已完成

M0 交付的是**面板自身**：身份、会话、安全入口、能力位图、审计日志，以及一个能直接验收
整条安全链路的内嵌页面。

已实现的说法全部给出**实现位置**（`文件:行 符号`）与**强制它的测试名**。行号会随并行改动漂移，
因此每条都可用 `grep -n` 复核；行为以代码为准。

| 能力 | 实现位置 | 强制它的测试 |
| --- | --- | --- |
| 单二进制：API + 内嵌前端，无 nginx / 无 PHP / 无 python venv | `cmd/minipanel/main.go:1-3` 包注释、`webui/embed.go:15 go:embed` | `make build` |
| CLI：`serve` `init` `doctor` `passwd` `reset-entrance` `version` | `cmd/minipanel/main.go:82 dispatch()` | `cmd/minipanel/main_test.go`（8 个用例）+ `make doctor`（实测通过） |
| 引导配置 `panel.json`（0600，原子写） | `internal/config/config.go:96 Save()` | `TestSaveAndLoadRoundTripWithPermissions` |
| SQLite 运行态存储 + 版本化迁移，文件强制 0600 | `internal/store/store.go:25 Open()`、`:64 migrate()`、`:50` chmod 循环（含 `-wal`/`-shm`） | `TestMigrationsAreIdempotentAndSeeded`、`TestFilePermissionsAreOwnerOnly`（只断言主文件，见 `docs/技术选型与MVP规格.md` §8.4） |
| 口令哈希 bcrypt cost 12、强度规则（长度≥10 且四类中三类） | `internal/sec/sec.go:20 HashPassword()`、`:55 ValidatePassword()` | `TestValidatePassword`、`TestPasswordHashIsSaltedAndVerifiable` |
| 登录 / 登出 / 会话（`mp_session` HttpOnly + SameSite=Strict） | `internal/api/auth.go:58 handleLogin()`、`:210 setSessionCookies()` | `TestLogoutAndRevokeSessions`、`TestSessionEndpointReportsIdentity` |
| 首个管理员引导（仅账号表为空时可用） | `internal/api/auth.go:139 handleSetup()` | `TestSetupOnlyWorksWhileNoUserExists`、`TestSetupRejectsWeakPasswordAndBadUsername` |
| 安全入口闸门 + 伪装响应 | `internal/api/server.go:187 entranceGate()`、`:233 disguise()` | `TestEntranceGateDisguisesEverythingElse` |
| 双提交 CSRF（`mp_csrf` Cookie ↔ `X-Mini-CSRF` 头） | `internal/api/server.go:312 csrf()` | `TestMutationsRequireCSRF` |
| 按 IP+用户名 的登录失败锁定，退避翻倍、上限 1 小时 | `internal/api/auth.go:81` key 组装、`internal/sec/ratelimit.go:62 Fail()` | `TestLoginLockoutAfterNFailures`、`TestRateLimiter` |
| TLS fail-closed 的凭据规则 | `internal/api/auth.go:50 credentialsAllowed()` | `TestCredentialsRefusedWithoutTLSThenListeningOnRoutableAddress` |
| 面板自签证书，SAN 跟随本机地址自动重签 | `internal/sec/tls.go:23 EnsureSelfSignedTLS()`、`cmd/minipanel/main.go:295 certHosts()` | **无自动化测试**（M0 测试缺口，见 `docs/技术选型与MVP规格.md` §8.4）；可复核 `make doctor` 的证书行与 `minipanel init` 的实际输出 |
| 两步验证 TOTP（RFC 6238，手写实现，无第三方 2FA 依赖） | `internal/sec/totp.go:35 TOTPCode()`、`internal/api/system.go:194 handleTOTPSetup()` | `TestTOTPVector`、`TestTOTPSetupEnableAndRequiredAtLogin` |
| 审计日志：只追加、敏感参数入库前掩码、另存 `params_hash` | `internal/audit/audit.go:34 Write()`、`:80 List()`、`:113 Mask()` | `TestWriteListAndMasking`、`TestMaskCoversTheShapesCredentialsArriveIn`、`TestAuditRecordsMutationsWithMaskedSecrets` |
| 能力位图与"禁用必须带理由"的契约 | `internal/platform/detect.go:18 newBase()`、`internal/platform/capabilities.go:123 Deny()` / `:131 Allow()` | `TestDetectedCapabilitiesAreExplained`、`TestCapabilitiesAreSelfConsistent` |
| 平台抽象（Linux / Windows / 其他，构建标签分文件） | `internal/platform/paths.go:10 Platform` | `TestPathsAreAbsoluteAndConsistent`、`make build-all` |
| 设置项白名单校验（IP 白名单 / 口令有效期 / basic_auth / trust_proxy） | `internal/api/system.go:78 editableSettings`、`:274 validateIPAllowlist()` | `TestSettingsAllowListAndValidation`、`TestIPAllowlistBlocksAuthenticatedSession` |
| OpenAPI 规格与路由表一一对应 | `internal/api/server.go:92 routes()`、`internal/api/openapi/panel.yaml` | `TestOpenAPIContractMatchesRoutes`、`TestSpecDeclaresTheSecurityContract` |
| 内嵌 M0 页面：登录/初始化、能力位图、系统信息、设置、审计、2FA、改密 | `webui/dist/index.html` | `make web`（存在性）+ 上述接口用例 |

**还没有做的（M0 明确不交付）**：站点、Nginx/Apache 配置、PHP 多版本与扩展、站点证书签发、
数据库、备份、计划任务、防火墙规则写入、服务启停、Web 终端、监控图表、文件权限管理、
SSH/RDP 管理页。这些在 UI 上不是"点击后无反应"，而是**灰掉并显示理由**，理由来自
`GET /api/v1/capabilities` 的 `unavailable` 字段（例如"数据库 Provider 在 M3 交付"）。
清单与理由的唯一来源是 `internal/platform/detect.go:61-78` 的拒绝表，一共 **16 项全部为 `false`
并各自带一句理由**；测试会拦下任何"关掉了却没理由"的项；反方向也拦：`capabilities_test.go:72`
的白名单声明**这个版本的 `features` 里只允许 `audit` 为 `true`**，所以"探测到本机有 ufw /
有 PHP 二进制"绝不会被报成一项功能（见下文能力位图一节与 `docs/技术选型与MVP规格.md` §8）。

---

## 快速开始

需要 Go 1.26 或以上（`go.mod:3` 的 `go` 指令是 `go 1.26.0`，这是工具链实际写入的下限，
不是历史计划里的 1.22）。

```bash
git clone https://github.com/Lisir2002/Mini_Panel
cd Mini_Panel

make build                     # 产物：bin/minipanel（CGO_ENABLED=0，纯静态）
sudo ./bin/minipanel init      # 写 panel.json（0600）、生成安全入口与面板证书
sudo ./bin/minipanel serve     # 前台启动；生产环境交给 systemd
```

init 结束会打印这样一段（`cmd/minipanel/main.go` 的 `bannerLines()`；入口是随机生成的 8 位串，
下面只是其中一次的样子，同一次运行里两行的入口一致）：

```
  Mini Panel 0.1.0-m0 · linux/amd64 · Ubuntu 22.04.5 LTS
  面板地址  https://服务器IP:29080/k7m2q9x4
  安全入口  /k7m2q9x4（未启用时任何路径都可打开登录页）
  TLS       开启 · 监听 0.0.0.0:29080
  未认证响应 404 · 登录失败上限 5 次
  数据目录  /var/lib/minipanel · 配置 /etc/minipanel/panel.json
  管理员账号 未创建 · 配置文件权限应为 0600
```

浏览器打开**带安全入口的完整地址**（`https://IP:29080/<入口>`），首次访问会要求创建管理员
账号（走 `POST /api/v1/setup`，只在账号表为空时可用）。

本机调试不必 root、也不必系统路径：`MINI_PANEL_ROOT` 会把 `/etc`、`/var` 前缀整体挪到一个
目录下（`internal/platform/platform_linux.go:25-30`）；`MINI_PANEL_DEBUG=1` 把日志级别降到
Debug（`cmd/minipanel/main.go:156 newLogger()`）——**注意目前非测试代码里没有任何 `.Debug()`
调用点**（`grep -rn "\.Debug(" --include='*.go' internal cmd | grep -v _test` 为空），所以今天
打开它不会多出任何输出，它是给后续埋点留的口子，不是"更多信息"开关：

```bash
make doctor    # 自检：路径 / 能力位图 / 数据库 / 证书（等价于 MINI_PANEL_ROOT=./data ... doctor）
make run       # 回环监听 127.0.0.1，数据落在 ./data
```

忘记入口或口令时，不需要面板可达，SSH 进去自救：

```bash
minipanel doctor                      # 现在是什么状态、入口是什么
minipanel passwd admin --password 'X' # 重置口令（账号不存在则创建）
minipanel passwd admin                # 不给 --password：在终端里隐藏输入（不回显）
minipanel reset-entrance              # 换一个安全入口（需重启面板生效）
```

---

## CLI 子命令

`minipanel` 不带参数等价于 `minipanel serve`（`cmd/minipanel/main.go:83-86`）；未知子命令报错并打印用法。
任何子命令加 `-h` 打印它自己的选项。出错时统一在 stderr 打 `minipanel: <原因>` 并**退出码 1**；
**未知 flag 不会静默忽略**——`minipanel init --bogus` 得到
`minipanel: flag provided but not defined: -bogus` 与退出码 1，这条是 Go flag 包的默认行为，
本仓库没有把 `fs.Usage` 换成"继续跑"的版本。`-h` 是提问不是失败，打印用法后**退出码 0**
（`main.go:70-78` 把 `flag.ErrHelp` 映射成 0）。

**这一节的每一条都有进程内测试压着**：`cmd/minipanel/main_test.go`（277 行、8 个用例，
`go test ./cmd/minipanel/`）。这些测试存在的原因写在文件头（`:17-20`）：M0 审计发现过一个
HTTP 测试永远看不见的缺陷——`minipanel init --port 29095 --bind 127.0.0.1` **把 flag 全收下、
一个都不生效、写的是默认值，然后打出一个看起来照办了的 banner**。所以下表每一条断言都从盘上
读回来验证（`readBack()` 用 `serve` 一样的方式 `config.Load`），完整叙述见
`docs/技术选型与MVP规格.md` §8.6。测试用 `MINI_PANEL_ROOT` 把 `/etc`、`/var` 挪进 `t.TempDir()`
（`isolated()`，`:26-30`），不会碰真实主机路径。

| 命令 | 选项 | 行为 / 退出（括号里是压它的测试） |
| --- | --- | --- |
| `minipanel serve` | `--bind <地址>`、`--port <端口>`、`--insecure-no-tls` | 前台运行。首次运行（没有 panel.json）会**就地执行 init**（`main.go:192`）。TLS 关闭且监听地址不是回环时打一条警告并照常启动，但登录接口会拒绝凭据（`main.go:201`）。收到 SIGINT/SIGTERM 后 10 秒优雅关闭（`main.go:266-275`）。（`serve -h` 由 `TestSubcommandHelpIsNotAFailure` 压） |
| `minipanel init` | `--bind`、`--port`、`--insecure-no-tls`、`--entrance </路径>` | 唯一被允许写引导值的命令（`main.go:337 cmdInit()`），写入 panel.json 并生成入口与自签证书。**每个 flag 都必须真的落到 panel.json**（`TestInitHonoursItsFlags`，`main_test.go:43`：端口/绑定/TLS 三项读回断言，另外 `main_test.go:70` 断言 `panel.json` 落盘 0600）。**不接受位置参数**（多给就报错，`main.go:347`；`--bogus` 与未知子命令一起由 `TestInitRejectsUnknownAndExtraArgs`（`main_test.go:75`）拒绝）。`--entrance -` 表示**关闭**入口，此时不会自动生成随机值（`main.go:368`；`TestInitEntranceFlag`（`main_test.go:88`）逐条压：`/myadmin` 原样、`myadmin` 自动补前导斜杠、`-` 关闭、`/api` 保留字拒绝、`/ab` 太短拒绝、`/../../etc` 穿越拒绝，并特意断言"空入口不得被重新解释成替我生成一个"） |
| `minipanel doctor` | `--json` | 打印/输出探测到的路径、能力位图、schema 版本、用户/会话/审计计数、数据库大小、证书 SAN 与到期、监听地址、入口（`main.go:462 cmdDoctor()`）。**不要求面板正在运行**，所以它是失联时的第一手诊断。入口未启用或没有账号时会给出下一步提示。（`doctor` 与 `doctor --json` 由 `TestResetEntranceKeepsConfigAndMirrorInStep` 顺带跑通 `main_test.go:150-155`） |
| `minipanel passwd <user>` | `--password '<口令>'` | 设置/重置管理员口令；账号不存在则创建。**用户名可以前置也可以后置**：`passwd admin --password 'X'` 与 `passwd --password 'X' admin` 都成立，因为 Go 的 flag 包遇到第一个位置参数就停止解析，代码为此把前置的用户名先摘出来（`main.go:581`）；给两个用户名则报错（`TestPasswdSetsMustChangeAndValidatesInput`，`main_test.go:174`）。口令省略时分两条路（`main.go:606` 用 `term.IsTerminal(os.Stdin)` 判断）：**tty 下走 `term.ReadPassword`（`main.go:612`），屏幕与终端缓冲区别人都读不到**，提示语是 `输入新口令: `，读完立刻换行；**管道下**（`echo 'X' | minipanel passwd admin`）不提示、直接 `readLine(os.Stdin)`（`main.go:621`），因为没有终端可隐藏。tty 这条是真关掉了回显——此前文案写"不回显"但没调 `term`，属于文案与行为不一致，已修（该分支需要真 pty，CI 里跑不到，缺口记在 §8.4）。口令强度按 `sec.ValidatePassword` 校验，**CLI 不豁免**（`--password short` 被拒；空 stdin 也被拒，同一测试 `main_test.go:204-214`）；非法用户名同样被拒。已有账号被改口令后，该用户**全部会话作废**，且下次登录要求修改口令（`MustChangePW`——测试 `main_test.go:193` 的理由就是"从 shell 传进去的口令不是操作者自己选的"）。 |
| `minipanel reset-entrance` | `--set </路径>`、`--disable` | 重新生成（或指定、或关闭）安全入口，写回 panel.json **并同步 settings 表的 `panel.entrance`**，两边必须一致（`TestResetEntranceKeepsConfigAndMirrorInStep`，`main_test.go:122`；`main_test.go:135` 与 `:143` 分别断言镜像值）。`--set` 与 `--disable` 同时给是**矛盾而不是优先级**，直接拒绝（`main_test.go:146`）。打印"需重启面板生效"。 |
| `minipanel version` | — | `Mini Panel <Version> (commit <Commit>, built <BuildDate>)`，三元组由 `-ldflags` 注入 `internal/build/build.go:4-8`。（`dispatch(["version"])` 返回 nil 由 `TestSubcommandHelpIsNotAFailure` 压；`TestUsageCoversEveryCommand`（`main_test.go:235`）还要求 6 个子命令与 8 个 flag 全部出现在 `usage` 文本里——帮助文档不许腐烂） |
| banner（`init`/`serve` 打的） | — | banner 里的端口、绑定地址、URL 必须等于**实际生效**的值；入口关闭时明写"未设置"而不是留空（`TestBannerReportsLiveConfigValues`，`main_test.go:252`，绑定回环时还禁止出现 `0.0.0.0`） |

---

## 安全模型

下面每一条都是**实现事实**，不是愿景；括号里是代码位置和压它的测试。

**1. 凭据接口 TLS fail-closed。** 一切携带口令的接口（`/api/v1/login`、`/api/v1/setup`）在
没有 TLS 时返回 `503 tls_required` 直接拒绝，而不是降级成明文。唯一例外是**监听地址是回环
且客户端也是回环**（`internal/api/auth.go:50 credentialsAllowed()`），这是给本机调试和
自动化测试留的口——一个监听在可路由地址上的面板拿不到这个捷径，因此生产环境里误写一行
`"tls": false` 的后果是登录不可用，而不是口令裸奔。
*为什么*：把口令的保密性寄托在"前端会加密再发"上是脆弱的——加密发生在客户端，一旦客户端
因为拿不到公钥之类的原因"为了可用性"回退成明文提交，服务端根本看不出来。所以这条规则收在
服务端，并且是拒绝而不是降级。

**2. 双提交 CSRF。** 非 GET/HEAD/OPTIONS 的请求必须带 `X-Mini-CSRF` 头，其值与服务端下发的
`mp_csrf` Cookie 常量时间比较（`internal/api/server.go:312 csrf()`，Cookie 与头名集中在 `:41-46` 的常量块）。
`mp_csrf` 故意可被 JS 读取（它就是双提交的另一半，见 `internal/api/auth.go:210 setSessionCookies()`
的注释），`mp_session` 是 HttpOnly + SameSite=Strict。
*为什么*：SameSite 已经是主防线，双提交是纵深防御，同时给前端一个稳定的、非会话级的令牌可用于
表单与上传请求。

**3. 登录失败锁定按 IP + 用户名计数。** key 是 `ip + "|" + username`（`internal/api/auth.go:81`），
超过 `panel.login_limit` 后锁定，锁定时长按窗口逐次翻倍、上限 1 小时
（`internal/sec/ratelimit.go:62 Fail()`，1 小时上限在 `:38`）。锁定期内
**即使口令正确也返回 429**，否则计数器只是建议。
*为什么按两个维度*：只按 IP 的话，攻击者拿一个用户名就能把整个办公网锁在外面；只按用户名的话，
单个账号就能被用来锁死某个管理员。计数状态**只在进程内存**里（`Limiter.cells`），取证记录落在
`login_events` 表（`internal/api/auth.go:231 recordLogin()`）；重启面板会清空内存中的锁定，
这是有意取舍——不把一张可被写坏的表变成登录的前置条件。

**4. 安全入口是未认证探测的伪装，不是鉴权层。** 配置入口后，未登录的请求访问入口之外的任何
路径，都按 `panel.unauth_status` 应答（400/401/403/404，或 444 直接断开连接）。应答体是一张
**中性的 HTML 错误页**，只有状态码文本，不含产品名与版本（`internal/api/server.go:234 disguise()`）。
*为什么不是 `http.Error`*：Go 默认那 10 字节 `text/plain` 的 "404 Not Found" 本身就是运行环境
指纹，而这条响应的全部意义是"探测者什么也学不到"；它同样**不伪装成 nginx 的错误页**——这个
进程就是 web server，给一张普通 404 是事实，冒充别人的错误页在事故响应时误导运维的程度不亚于
误导扫描器。`/healthz` 例外，监控探针不能被藏起来。直接 POST `/api/v1/login` 而没先访问过入口，
同样按伪装应答——判断依据是访问入口时种下的 `mp_entrance` 标记 Cookie 与服务端配置值的常量时间
比较（`internal/api/server.go:219 entranceMarked()`）。

**持有合法 `mp_session` 之后，任何路径都可以访问**（`internal/api/server.go:198` 的 `hasSession(r)`
分支，`hasSession` 在 `:214`）。这是**有意的**设计，不是遗漏：SPA 必须能在导航、刷新、落到深链时
继续工作，把这些请求统统改写成一个魔法路径换来的是一个勾，代价是一个不能用的界面。因此：

* 入口**不能缓解 XSS，也不能缓解 Cookie 泄露**。拿到会话就等于拿到整个面板；任何"安全入口保护
  登录后的面板"的说法都是错的。
* 穿过闸门之后真正的判定只剩 `requireSession`（`internal/api/server.go:260`）——伪造一个像样的
  会话值能过闸门，但过不了会话查表，仍然拿到伪装响应。
* 进一步的收紧（对 HTML 导航逐路径校验入口）是 **M1 待办**，见 `docs/里程碑.md`，在实现之前
  文档里不得把它写成现状。

*为什么必须说清楚*：真正的访问控制是**监听地址 + 会话令牌与有效期 + 可选 IP 白名单**
（`panel.ip_allowlist`，`internal/api/server.go:287 ipAllowed()`）+ CSRF + 登录锁定。入口路径写进
panel.json（0600）且被 `.gitignore` 排除，`GET /api/v1/settings` 也刻意不回显它的值（只说
"已启用"），要看真值请用 `minipanel doctor`——伪装只在没人拿到配置文件的前提下成立。

**5. 审计日志只追加。** `internal/audit` 包里**不存在删除或清空的方法**（`audit.go:78-80` 的注释
与 `Write`/`List` 两个导出方法就是全部），接口面上也没有任何 `DELETE /audit`；每条写操作
（成功或失败）都落一行（`internal/api/server.go:330 auditWrites()`）。口令、`token`、`key`、`pem`、
`cookie` 等敏感形状的字段入库前掩码成 `***`（`internal/audit/audit.go:113 Mask()`），同时保存一份
对**未掩码原值**的 SHA-256 `params_hash`（`audit.go:48-56`）。
*为什么*：能被被审计者抹掉的审计日志是装饰品；而 `params_hash` 让事后比对"这两次请求是不是同一个
凭据"不必保存凭据本身。

**6. 没有反射式接口。** 路由表里每条路径对应一个处理函数
（`internal/api/server.go:92 routes()`），整个 API 里唯一的**路径参数是 `/api/v1/settings/{key}`**，
而且它的取值还要再过一次 `editableSettings` 白名单（`internal/api/system.go:78`），不在表里
直接 `400 immutable`。契约测试会扫描 OpenAPI 规格，出现 `mod_name`、`{action}`、`{module}`
这类片段就失败（`internal/api/contract_test.go:70 TestSpecDeclaresTheSecurityContract()`）。
*为什么*：把 `mod` / `class` / `action` 这类请求参数直接映射到内部包里的任意公开方法，是同类
面板历史上一串越权与 RCE 链的根因；一个自己写的面板只要留出"参数→函数名"的通道，迟早会长出
同样的洞。引导值（端口、入口、TLS、会话时长）不能通过 API 修改，必须改文件 + 重启，也是同一条
原则的延伸：被盗用的会话不该能把面板从运维脚下搬走。

**7. 未知用户与错误口令不可区分。** 两者返回完全相同的状态码与响应体
（`internal/api/auth.go:94-99`），杜绝账号枚举。

**8. 无遥测，无任何外部上传。** `/healthz` 里 `telemetry:false`（`internal/api/system.go:22 handleHealth()`），
而且非测试代码里**没有任何出站 HTTP/拨号调用**——`grep -rnE
"http\.(Get|Post|Client|DefaultClient)|net\.Dial\(" --include='*.go' .` 排除 `*_test.go` 后为空，
这条可以当命令复核。崩溃信息、许可证校验、版本检查都不存在。

**9. 其它基线。** 响应头固定 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
`Referrer-Policy: no-referrer`、`Cache-Control: no-store`，TLS 下追加 HSTS
（`internal/api/server.go:148 securityHeaders()`）；`MinVersion: TLS 1.2`（`main.go:237`）。
`X-Forwarded-For` 默认不信任，只有 `panel.trust_proxy=true` 时才解析，且启动时会打警告——
开了它，扫描器就能伪造来源地址绕过按 IP 的锁定（`internal/api/server.go:54 var trustProxy`、
`:407 clientIP()`）。请求体与审计缓冲都有上限（1 MiB / 8 KiB，`server.go:438`、`:342`），
没有全局 `WriteTimeout`（M4 的终端 WebSocket 会被它切断），只有
`ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout`（`main.go:231-233`）。

---

## 能力位图契约与前端的诚实性约定

`GET /api/v1/capabilities` 返回 `internal/platform.Capabilities`
（`internal/platform/capabilities.go:89`），它是**前端渲染的唯一依据**：

* `features` 里为 `true` 的项 → 渲染成可用控件；
* `features` 里为 `false` 的项 → 必须能在 `unavailable` 里找到一句人能读懂的理由，UI 渲染成
  "灰掉 + 理由"（`webui/dist/index.html` 里读 `caps.features` / `caps.unavailable` 的那段渲染，
  兜底文案是常量 `NO_REASON`；用 `grep -n 'NO_REASON\|unavailable' webui/dist/index.html` 复核，
  这个文件正在被并行改动，行号不作准）；
* **绝不渲染"看着能点、点了没反应"的按钮**，也绝不像某些实现那样把没实现的功能整块藏起来。
  前者让人以为坏了反复报障，后者让人以为产品没有这个能力。

保障是测试而不是口头约定：

* `TestDetectedCapabilitiesAreExplained`（`internal/platform/capabilities_test.go:41`）——
  对当前主机真实探测，任何 `false` 却没理由即失败；并且用**白名单**断言反向收紧
  （`capabilities_test.go:72 implemented := map[string]bool{FeatAudit: true}`）：`features` 里
  出现白名单之外的任何 `true` 即失败，白名单里的项报成 `false` 同样失败。也就是说本版本
  **只有 `audit` 算"已交付功能"**；哪天平台探测（`Detect`）因为"看到了某个机制"就 `Allow` 一项
  还没有实现的特性，测试会直接红，这条纪律写在 `docs/技术选型与MVP规格.md` §8。
* `TestCapabilitiesAreSelfConsistent`（`internal/api/m0_test.go`，从 HTTP 外面再打一遍同一条规则）；
* `TestDenyAndAllowAreSymmetric`（`internal/platform/capabilities_test.go:9`）——`Allow` 必须
  清掉旧理由，`Deny` 未知项不得 panic。

`make check-honesty` 就是这三条。

探测的规则是"只报本机当场验证过的"：`newBase()` 先把所有功能置为 `false` 并填好理由
（`internal/platform/detect.go:18`，拒绝表在 `:61`），平台实现只能对自己确实检查到的部分调
`Allow()`——**而 M0 里没有任何平台调用过 `Allow()`**（复核：
`grep -rn "\.Allow(" --include='*.go' internal/platform | grep -v _test` 为空），
`features` 中唯一为 `true` 的是 `detect.go:54` 的 `audit`。探测到的事实（装了 ufw、跑着 sshd、
有 nginx）只写进 `Capabilities` 的描述字段，绝不成了一项能力。
Linux 上 `ufw`/`firewall-cmd`/`nft` 都没装与装了但没有写入 Provider，是**两句不同的理由**
——原文分别是 `"未检测到 ufw / firewall-cmd / nft 任一后端，本机没有可管理的防火墙"`
（`internal/platform/platform_linux.go:81`）与 `"当前版本只读展示后端状态；规则写入 Provider 在 M4 交付"`
（`:83`），`:77-79` 的注释写的就是这条区分："no firewall software on this host" 与
"firewall present, write provider not shipped yet" 必须由 UI 区分开。Windows 的差异同样体现在位图里：PHP 只有 `php-cgi.exe`
的 FastCGI 进程池（没有 php-fpm）、扩展只能装与 PHP 版本 × TS/NTS × VC 运行库 × 位数完全匹配的
预编译 DLL、reload 只有 `restart_only`、防火墙是 WFP、计划任务走 `schtasks`
（`internal/platform/platform_windows.go:45-101 Detect()`）。

`internal/platform` 之外**没有任何 `runtime.GOOS` 分支**，平台差异靠构建标签分文件
（`platform_linux.go` / `platform_windows.go` / `platform_other.go`），这条也可以当命令复核：
`grep -rn "runtime.GOOS" --include='*.go' . | grep -v internal/platform` 只剩注释里的说明。

---

## 配置与存储的分界

* `panel.json`（`internal/config/config.go`）只放**数据库还没通就得知道的引导值**：
  `bind`、`port`、`entrance`、`tls`、`hosts`、`data_dir`、`log_dir`、`session_ttl`、
  `login_limit`、`unauth_status`。字段是带类型的，写文件走 `tmp + rename` 原子替换并固定 0600
  （`config.go:96-109`）。
  `session_ttl` 是 `Duration` 类型，既接受 `"12h"` 也接受纳秒整数（`config.go:36-59`），
  防止手改的 `"12h"` 被读成 12 纳秒；`Validate()`（`config.go:111-133`）对端口、bind、
  `unauth_status` 取值集合（400/401/403/404/444）是**报错**，对 `session_ttl < 1m` 与
  `login_limit <= 0` 是**修复成默认值**——明显的笔误不该把面板锁死。
* `minipanel.db`（SQLite，`internal/store/store.go:64-181`）放**运行态**：users / sessions /
  login_events / audit / settings。schema 有版本，比二进制新就拒绝降级启动。
* 分界的理由：不再用"某个数据文件存不存在"来表达状态。那种"空文件=开启、UI 显示相反"的
  歧义是这个项目拒绝复制的东西（`store.go:1-7`）；每个开关都是带类型、有校验的一行。
* 引导值不进 API 写路径（见上文第 6 条）。`GET /api/v1/settings` 的每一项带 `source`：
  `db` 是运行态可写值（存在 SQLite），`panel.json` 表示这是**进程当前真正在用的引导值**
  （`internal/api/system.go:108-116` 命中 `runtimeSetting()`（`:127`）时用进程值覆盖表里的镜像）。
  因此 **SQLite 里的 `panel.port` 只是初始化镜像，不是第二真源**——按镜像显示会出现
  "设置页写着 29080、实际监听别的端口"的假象。`panel.entrance` 的 `source` 是 `panel.json`，
  但值**永远不是入口路径本身**，只有"已启用（值不在此展示，见 panel.json 或 minipanel doctor）"
  或"已关闭"（`system.go:132-138`）：设置页是最容易被截图的地方，而入口是伪装手段，
  要看真值请用 `minipanel doctor`。
* 数据目录里的文件权限由代码主动收紧：`minipanel.db` 及 `-wal`/`-shm` 一律 0600
  （`store.go:46-57`），面板证书与私钥 0600（`internal/sec/tls.go:71-88`）。
  **注意覆盖面**：`TestFilePermissionsAreOwnerOnly` 只断言主文件，`-wal`/`-shm` 与证书/私钥
  是"代码保证、暂无断言"，缺口清单见 `docs/技术选型与MVP规格.md` §8.4。

---

## 构建

```
make build              当前平台 → bin/minipanel
make build-windows      windows/amd64 → bin/minipanel-windows-amd64.exe
make build-all          linux/darwin/windows/freebsd × amd64/arm64 共 8 个产物
make test               go test -count=1 ./...
make vet                go vet ./...
make fmt                gofmt -s -w .（正常应当没有任何 diff）
make check-contract     路由表 ↔ openapi/panel.yaml 对齐
make check-honesty      能力位图自洽
make doctor             自检（数据落在 ./data，不动系统路径）
make run                本机调试，127.0.0.1 监听
make web                说明前端无构建步骤，并检查 index.html 存在
make tidy               go mod tidy
make clean              只删 bin/
```

全程 `CGO_ENABLED=0`：SQLite 用纯 Go 驱动 `modernc.org/sqlite`，所以交叉编译不需要目标平台
有 C 工具链，产物也不依赖目标机的 glibc。**8 个组合（linux / darwin / windows / freebsd ×
amd64 / arm64）在这台开发机上逐条实测全部退出码 0**，其中 linux/amd64、linux/arm64、
darwin/arm64、windows/amd64、freebsd/amd64 是**重点目标**（四个 OS 都覆盖到，且是实际部署最常见的
那批架构）；
此外 `GOOS=windows|darwin|freebsd|linux go vet ./internal/...` 也都退出码 0（平台专属的接口误用
不会留到发布日，复核命令见 `docs/技术选型与MVP规格.md` §6）。
后加的 `golang.org/x/term`（`minipanel passwd` 的隐藏输入）不改变这条矩阵：它与 `x/crypto`、
`x/sys` 同属标准库同族，纯 syscall、无 cgo，唯一依赖是 `x/sys`；加上它之后 8 个组合重新实测
仍然全部产出（见下方"如何验证"）。

**前端没有构建步骤**：`webui/dist/index.html` 是手写的单文件页面，由 `webui/embed.go` 的
`//go:embed all:dist` 打进二进制，**必须入库**（`.gitignore` 里专门写了注释防止有人再把它
加回忽略列表）。M1 起会换成 Vue 3 + Vite + Element Plus 的工程，产物仍然输出到 `webui/dist`，
接口面不变。

版本注入：`make build` 用 `-ldflags -X` 写入 `internal/build` 的 `Version`/`Commit`/`BuildDate`，
`make version` 或 `minipanel version` 可验证。

---

## 如何验证

正文里的每条说法都自带复核方式（`grep -n`、测试名或 make 目标）。这里集中记一次开发机上的
实测结果，作为"照着 README 走能不能跑通"的证据。环境：Ubuntu 22.04.5 LTS、`go1.26.0 linux/amd64`、
`CGO_ENABLED=0`。

| 命令 | 实测结果 |
| --- | --- |
| `make vet` | `go vet ./...` 无输出 |
| `make test` | **全绿，且没有随机失败**：`internal/api` 10.3s、`internal/sec` 1.0s、`internal/store` 0.2s、`internal/audit` 0.14s、`internal/config` 0.003s、`internal/platform` 0.002s、`cmd/minipanel` 1.2s（新入库的 `cmd/minipanel/main_test.go`，8 个 CLI 用例，见上文"CLI 子命令"）；`webui` 无测试文件（零依赖单文件前端，它的契约由后端返回的字段名约束）。曾经约 1/5 概率飘红的入口字母表矛盾**已由源码侧修掉**：`go test -count=60`/`-count=200 -run TestEntranceShape ./internal/sec/` 本轮都 ok；历史、原因与防回归口径见 `docs/技术选型与MVP规格.md` §8.3 |
| `make fmt` | `gofmt -s -l .` 执行前后都为空，且没有任何 `.go` 的 mtime 变化——**fmt 不产生 diff 是预期状态** |
| `make check-contract` | `ok … internal/api 0.004s`（`TestOpenAPIContractMatchesRoutes` + `TestSpecDeclaresTheSecurityContract`） |
| `make check-honesty` | `ok … internal/platform 0.002s`、`ok … internal/api 0.571s`（三条能力契约测试 + HTTP 面重述） |
| `make build && ./bin/minipanel version` | `Mini Panel 0.1.0-m0 (commit ca2990d, built 2026-11-10T22:15:14Z)`；产物 12,333,218 字节。commit / built 由 Makefile 从 `git rev-parse --short HEAD`（取不到就写 `none`，`Makefile` 第 18 行）与 UTC 当前时间（第 19 行）注入，第 21-24 行的 `-ldflags -X $(MODULE)/internal/build.{Version,Commit,BuildDate}` 落到 `internal/build`，**每次构建都会变**，不是可以对表的常量 |
| `make build-all` | 8 个产物全部产出，11.3–12.4 MB，末行打印 `build-all OK`（加入 `golang.org/x/term` 之后重跑，结论不变；`CGO_ENABLED=0` 见 `go version -m bin/minipanel`） |
| `make doctor` | 打印平台、路径（`MINI_PANEL_ROOT=./data`，不动系统路径）、schema v1、用户/会话/审计计数、证书、监听与未认证响应，并逐条列出**未开放能力及理由**（末行可见 `backup(备份任务与归档管理在 M6 交付)`、`cron(计划任务调度器在 M6 交付)`，与 `internal/platform/detect.go:68-69` 原文一致） |
| 8 个组合逐条 `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build`（linux/darwin/windows/freebsd × amd64/arm64） | **8/8 退出码 0**（本轮逐个跑，产物 15.8–17.5 MB，未加 `-s -w`；带 ldflags 的 `make build-all` 产物是 11.3–12.4 MB） |
| `GOOS=linux\|windows\|darwin\|freebsd go vet ./internal/...` | 四个平台全部退出码 0、无输出 |
| `go test ./cmd/minipanel/` | `ok … 1.17s`——`init` 的 flag 真的落到 panel.json、未知 flag/位置参数/未知子命令报错、`--entrance -` 关闭入口、`reset-entrance` 同步 settings 镜像、`passwd` 校验与 `must_change_pw`、`-h` 不算失败、usage 与命令表一致、banner 显示在用值 |
| `go test -count=60 -run TestEntranceShape ./internal/sec/`；`-count=200` | 两者都 `ok`——曾经约 1/5 概率飘红的入口字母表矛盾已修（`internal/sec/sec.go:108-115` 注释写明原因与熵算法），这两条是它的回归口径，见 `docs/技术选型与MVP规格.md` §8.3 |
| `go mod tidy -diff` | 无输出（`go.mod`/`go.sum` 已 tidy；因此不必执行 `make tidy`） |
| `sed -n '5,12p' go.mod`；`grep -c '// indirect' go.mod` | 直接依赖 6 个（含 `golang.org/x/term v0.48.0`）、间接 15 个 |
| `grep -rn "golang.org/x/term" --include='*.go' .` | 只有一处：`cmd/minipanel/main.go:42`——这个依赖只为隐藏口令输入而存在 |
| `echo 'X' \| minipanel passwd admin`（管道） | 退出码 0，输出"已更新 admin 的口令，作废 0 个会话…"，**不打提示语**（没有终端可隐藏，`main.go:621 readLine`） |
| `minipanel passwd admin`（真 tty） | 只显示 `输入新口令: ` 与随后的换行；用 `pty.fork()` 造终端、只检查主端回流的字节，输入口令后在主端流里搜不到明文——回显确实被关掉了（`main.go:606 term.IsTerminal` → `:612 term.ReadPassword`）。这条现在是代码事实，不再只是文案 |
| `grep -rnE "http\.(Get\|Post\|Client\|DefaultClient)\|net\.Dial\(" --include='*.go' . \| grep -v _test.go` | 空——**没有遥测** |
| `grep -rn "runtime.GOOS" --include='*.go' . \| grep -v internal/platform` | 空——平台差异只靠构建标签 |
| `grep -rn "\.Allow(" --include='*.go' internal/platform \| grep -v _test` | 空——**M0 没有把任何探测结果报成功能**，`features` 里唯一为真的是 `audit` |
| `minipanel doctor --json`（本机实测） | `features` 中为 `true` 的只有 `audit` 一项；16 项为 `false`，且 `unavailable` 恰好 16 条理由——一条"关掉了没理由"的都没有 |

> 如果你把仓库放进自己的 git 远端，记得先确认 `webui/dist/index.html` 被跟踪：
> `git ls-files webui/dist` 应该有输出，`git check-ignore -v webui/dist/index.html` 应该**没有**命中。
> `.gitignore` 里专门写了注释解释为什么这一条不能进忽略列表。

---

## 里程碑

里程碑内容与代码注释里的交付标记一一对应（拒绝在这里写"快有了"）。**唯一例外是 M5**：代码里
没有 "M5" 字样，它是项目定位（Linux 先行、抽象层第一天就为 Windows 服务），所以 M5 那一行只写
"收敛成 GA" 的验收，不写任何新组件。

| 里程碑 | 范围 | 代码里的标记 |
| --- | --- | --- |
| **M0 已完成** | 身份与会话、安全入口与伪装、TLS fail-closed、CSRF、登录锁定、TOTP、审计日志、能力位图契约、OpenAPI 契约测试、平台探测与路径抽象、内嵌 M0 页面、单二进制交叉编译 | `internal/platform/detect.go:36-42` 的注释即 M0 范围定义 |
| **M1 账号与会话** | 账号/会话管理页替代 M0 引导路径；前端工程化（Vue 3 + Vite + Element Plus，产物仍进 `webui/dist`）；**收紧入口边界：对 HTML 导航逐路径校验入口**（M0 的现状是"有合法会话后任何路径可访问"，因此入口不缓解 XSS / Cookie 泄露） | `internal/api/server.go` 的 `entranceGate()` 注释里把这条列为 M1 项，并明确要求在实现前不得描述成现状 |
| **M2 站点、PHP 与站点证书** | Nginx/Apache 站点创建与配置生成、站点写入、PHP 多版本安装与版本切换、扩展安装、站点证书签发与部署；Windows 侧对应 php-cgi 进程池 | "站点创建与 Nginx 配置生成在 M2 交付"、"PHP 多版本安装在 M2 交付"、"PHP 版本切换在 M2 交付"、"PHP 扩展编译安装在 M2 交付"、"站点证书签发与部署随 Nginx Provider 在 M2 交付" |
| **M3 数据库** | 数据库 Provider | "数据库 Provider 在 M3 交付" |
| **M4 主机管理** | 防火墙规则写入、服务启停、Web 终端与录像审计、监控采集与图表、文件权限（随文件管理器）、SSH/RDP 访问管理页 | "防火墙规则写入在 M4 交付"、"服务启停在 M4 交付"、"Web 终端与录像审计在 M4 交付"、"监控采集与图表在 M4 交付"、"文件权限（属主/模式）管理随文件管理器在 M4 交付"、"SSH/RDP 访问管理页在 M4 交付" |
| **M5 Windows 完整支持** | 不引入新功能：把散在 M0（探测/路径/位图）、M2（php-cgi 池、预编译 DLL）、M4（WFP 写入、SCM 启停、远程访问页）的 Windows 部分收敛成受支持的 GA——Windows 上的安装/升级/回滚、M2+M4 全部功能在 Windows CI 有断言、伪装与入口在 IIS-less 部署下可用 | 代码里**没有**以 "M5" 为理由的 Deny 文案（`grep -rn "M5" --include='*.go' .` 为空），M5 是项目定位；已存在的 Windows 约束逐条在 `internal/platform/platform_windows.go:45-101`。完成定义见 `docs/里程碑.md` M5 一节 |
| **M6 计划任务与备份** | 计划任务调度器（内置 + `crontab`/`taskschd`）、备份任务与归档管理 | "计划任务调度器在 M6 交付"（`internal/platform/detect.go:69`）、"备份任务与归档管理在 M6 交付"（`:68`） |
| 未排期（不占里程碑编号） | 子账号：把 `SessionUser` 的具体用户名变成富主体里的一个字段 | `internal/api/server.go:391` 的注释写着 "M6 (sub-accounts)"，但代码里既没有对应的 feature 名也没有 Deny 理由，所以本文档把它记为**未排期**、不占用 M6 编号（M6 只装调度器与备份这两件已有原文的事）；要正式排期，先在位图里给它一个条目 |

> Windows 的工作是**分布式的**：M0 就写进了探测/路径/能力位图，写操作分别随 M2（php-cgi 池、
> 预编译 DLL）与 M4（WFP 防火墙 Provider、SCM 服务启停、远程访问页）交付；**M5 不是"再补一批
> Windows 代码"**，它的含义是把这些分布的能力收敛成有安装/升级/回滚路径、有 CI、可对外承诺的版本。
> 反过来说，"完整支持"也不等于和 Linux 逐字节相同——POSIX 权限位在 Windows 上没有对应物，
> 位图里那句 `"Windows 使用 ACL 与继承，POSIX 权限位仅作只读展示"`（`platform_windows.go:55`）
> 是永久差异，不会被哪个里程碑消掉。

验收标准逐条见 `docs/里程碑.md`。

---

## 隐私声明

Mini Panel **不发送任何遥测**：没有崩溃上报、没有许可校验、没有版本检查、没有"回传官方"的调用。
非测试代码里不存在出站 HTTP/拨号（见安全模型第 8 条的复核命令）。审计日志、登录事件、口令哈希、
会话全部留在本机 `minipanel.db` 里，`/healthz` 的 `telemetry:false` 是这一事实的声明而不是开关。

## 文档

* `docs/技术选型与MVP规格.md` —— 技术栈理由、平台抽象层与能力位图契约（§2，被
  `internal/platform/capabilities.go` 的包注释引用）、OpenAPI 契约、配置与存储分界、安全模型、
  交叉编译矩阵（§6，被 `Makefile` 引用）、MVP 边界、**§8 已知缺陷与不接受的做法**
* `docs/里程碑.md` —— M0..M6 的验收标准与当前状态（M5 = Windows 完整支持，M6 = 计划任务与备份）
