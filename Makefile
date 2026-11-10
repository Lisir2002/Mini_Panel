# Mini Panel — 构建 / 自检入口
#
# 三条硬约束（详见 README.md 与 docs/技术选型与MVP规格.md）：
#   * CGO_ENABLED=0：SQLite 用纯 Go 驱动 modernc.org/sqlite，所以任意目标平台
#     都能交叉编译，目标机不需要工具链，本机也不需要 C 编译器。
#   * 没有前端构建步骤：webui/dist/index.html 是手写的静态文件，直接 embed 进二进制。
#   * 版本三元组由 internal/build 持有，链接时用 -ldflags 注入。

MODULE     := github.com/Lisir2002/Mini_Panel
BINARY     := minipanel
CMD        := ./cmd/minipanel
BUILD_DIR  := bin

GO := go

# 发布时覆盖，例如 make build-all VERSION=v0.2.0
VERSION    ?= 0.1.0-m0
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(MODULE)/internal/build.Version=$(VERSION) \
  -X $(MODULE)/internal/build.Commit=$(COMMIT) \
  -X $(MODULE)/internal/build.BuildDate=$(BUILD_DATE)

# 必须能编过的平台组合（docs/技术选型与MVP规格.md §6）。
# 8 个是完整矩阵；其中 linux/amd64、linux/arm64、darwin/arm64、windows/amd64、
# freebsd/amd64 这 5 个是逐条实测过的重点目标（另外 3 个由 build-all 顺带覆盖）。
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
  windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64

GOOS_CUR := $(shell $(GO) env GOOS 2>/dev/null)
EXE      := $(if $(filter windows,$(GOOS_CUR)),.exe,)

# make run / make doctor 的落地目录。MINI_PANEL_ROOT 把 /etc、/var 前缀挪到这里
# （internal/platform/platform_linux.go 的 rooted()），因此本机调试既不需要 root，
# 也不会污染系统路径；该目录已在 .gitignore 中。
MINI_PANEL_ROOT ?= $(CURDIR)/data

.PHONY: all build build-windows build-all test vet fmt tidy run doctor web \
  check-contract check-honesty clean version

all: build

## build  编译当前平台，产物 bin/minipanel
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)$(EXE) $(CMD)

## build-windows  交叉编译 Windows/amd64（单一 .exe，含服务与内嵌 UI）
build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)

## build-all  linux/darwin/windows/freebsd × amd64/arm64 全交叉编译
build-all:
	@mkdir -p $(BUILD_DIR)
	@for p in $(PLATFORMS); do \
	  os=`echo $$p | cut -d/ -f1`; arch=`echo $$p | cut -d/ -f2`; \
	  ext=; if [ "$$os" = windows ]; then ext=.exe; fi; \
	  out=$(BUILD_DIR)/$(BINARY)-$$os-$$arch$$ext; \
	  echo "  GOOS=$$os GOARCH=$$arch -> $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $$out $(CMD) || exit 1; \
	done
	@echo "build-all OK"

## test  全部单元测试（含 M0 验收用例与契约用例）
test:
	$(GO) test -count=1 ./...

## vet  go vet
vet:
	$(GO) vet ./...

## fmt  gofmt；本仓库源码本应已符合格式，运行后不应产生任何 diff
fmt:
	gofmt -s -w .

## tidy  go mod tidy
tidy:
	$(GO) mod tidy

## run  本机调试启动：回环监听 + 独立数据目录，首次运行自动初始化
run: build
	@echo "  MINI_PANEL_ROOT=$(MINI_PANEL_ROOT)  监听 127.0.0.1，Ctrl-C 退出"
	MINI_PANEL_ROOT=$(MINI_PANEL_ROOT) ./$(BUILD_DIR)/$(BINARY)$(EXE) serve --bind 127.0.0.1

## doctor  自检：路径 / 能力位图 / 数据库 / 证书；面板不运行也能执行
doctor: build
	MINI_PANEL_ROOT=$(MINI_PANEL_ROOT) ./$(BUILD_DIR)/$(BINARY)$(EXE) doctor

## version  打印版本三元组，用于确认 -ldflags 注入生效
version: build
	./$(BUILD_DIR)/$(BINARY)$(EXE) version

## web  前端说明：M0 没有构建步骤，此目标只做存在性检查
web:
	@echo "前端是手写的静态文件 webui/dist/index.html：无 npm、无 Vite、无构建步骤。"
	@echo "它由 webui/embed.go 的 //go:embed all:dist 打进二进制，因此 index.html 必须入库。"
	@test -f webui/dist/index.html || { echo "ERROR: webui/dist/index.html 缺失"; exit 1; }
	@echo "OK: webui/dist/index.html 存在（`wc -c < webui/dist/index.html` 字节）"

## check-contract  路由表与 openapi/panel.yaml 必须一一对应
check-contract:
	$(GO) test -count=1 -run 'TestOpenAPIContractMatchesRoutes|TestSpecDeclaresTheSecurityContract' ./internal/api/

## check-honesty  能力位图自洽：features=false 的每一项都必须带可读理由
check-honesty:
	$(GO) test -count=1 -run 'TestDetectedCapabilitiesAreExplained|TestDenyAndAllowAreSymmetric|TestPathsAreAbsoluteAndConsistent' ./internal/platform/
	$(GO) test -count=1 -run 'TestCapabilitiesAreSelfConsistent' ./internal/api/

## clean  只删构建产物；$(MINI_PANEL_ROOT) 里的 panel.json / minipanel.db 是运维数据，故意不删
clean:
	rm -rf $(BUILD_DIR)
