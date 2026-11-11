package api

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Lisir2002/Mini_Panel/internal/platform"
)

// 这三条把"前端与后端不许各说一套"从注释升级成会失败的检查。
//
// M0 的前端是一个手写 HTML，M1 换成 Vue 3 + Vite + Element Plus 之后，最容易悄悄
// 坏掉的正是三件在旧版本里由"只有一行字符串"保证的事：产物仍然自包含、每一项能力
// 都还有地方显示、每一个登记的端点都还有人调用。

// TestUIBundleIsASingleSelfContainedFile 守的是安全入口的一条隐含前提：
// 闸门对"入口之外、且没有会话"的请求一律回伪装响应（entranceGate）。因此登录页
// 需要的每一个字节都必须来自同一个响应——只要产物里还剩下一个 /assets/*.js 或
// 外部字体，未登录的人就会去请求一条入口外的路径，拿到一个伪装成 404 的 <script>，
// 表现为"打开入口是一片空白"。这类缺陷不会报错，只会让人以为面板坏了。
func TestUIBundleIsASingleSelfContainedFile(t *testing.T) {
	assets := embeddedUI()
	if assets == nil {
		t.Skip("前端未编译（webui/dist 为空），跳过：请执行 make web 后重新构建")
	}
	var files []string
	err := fs.WalkDir(assets, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历前端产物: %v", err)
	}
	sort.Strings(files)
	if len(files) != 1 || files[0] != "index.html" {
		t.Errorf("产物必须是单个 index.html，实际是 %v；"+
			"多出来的文件都住在安全入口之外，未登录时会被闸门伪装掉", files)
	}

	b, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("读取 index.html: %v", err)
	}
	html := string(b)
	// 只看 HTML/CSS 部分：内联 <script> 里 Element Plus 自己的 JS 源码含有
	// `url('${P}')` 这类模板字符串，扫它会误报。真正决定"登录页要不要再发一次
	// 入口外的请求"的是标记与样式，不是脚本正文。
	markup := regexp.MustCompile(`(?s)<script[^>]*>.*?</script>`).ReplaceAllString(html, "")
	// RE2 没有先行断言，所以先把候选都取出来，再按内容判定。
	// 允许的非文件引用：data: URI（图标内联）、#fragment（内联 SVG 的渐变/遮罩）。
	inline := func(s string) bool {
		s = strings.Trim(s, `'"`)
		return strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "#")
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="([^"]*)"`).FindAllStringSubmatch(markup, -1) {
		if !inline(m[1]) {
			t.Errorf("产物里存在外部引用 src/href=%q：登录页将依赖安全入口之外的路径", m[1])
			break
		}
	}
	for _, m := range regexp.MustCompile(`url\(([^)]*)\)`).FindAllStringSubmatch(markup, -1) {
		if !inline(m[1]) {
			t.Errorf("产物里存在外部引用 url(%s)：登录页将依赖安全入口之外的路径", m[1])
			break
		}
	}
}

// TestUIDeclaresEveryCapabilityKey 是 M0 验收第 18 条（"UI 上未交付项显示为灰 + 理由，
// 不存在点了没反应的按钮"）在换代之后的等价物：后端探测到的每一个 feature key，
// 前端都必须有对应的字面量。少一个，那一行就变成"未上报"或者干脆消失——而这两种
// 都不会有人报错。
func TestUIDeclaresEveryCapabilityKey(t *testing.T) {
	assets := embeddedUI()
	if assets == nil {
		t.Skip("前端未编译，跳过")
	}
	b, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("读取 index.html: %v", err)
	}
	html := string(b)

	caps, err := platform.Current().Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(caps.Features) == 0 {
		t.Fatal("能力位图为空，这条测试失去意义")
	}
	var missing []string
	for key := range caps.Features {
		if !strings.Contains(html, `"`+key+`"`) {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("后端报了 %d 项能力，前端没有登记这些 key：%v", len(caps.Features), missing)
	}
}

// TestUIReachesEveryDocumentedEndpoint 让 openapi/panel.yaml 反过来受前端约束：
// 规格里登记的每一条路径，产物里都要出现一次。它挡的是另一种漂移——加了端点、
// 写了规格、页面却根本没接（于是"接口面存在但面板上没有入口"，正是我们在参照系里
// 批评过的"有按钮无逻辑"的反面版本：有逻辑无按钮）。
func TestUIReachesEveryDocumentedEndpoint(t *testing.T) {
	assets := embeddedUI()
	if assets == nil {
		t.Skip("前端未编译，跳过")
	}
	b, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatalf("读取 index.html: %v", err)
	}
	html := string(b)

	ops := specOperations(t, filepath.Join("openapi", "panel.yaml"))
	seen := map[string]bool{}
	for op := range ops {
		_, path, _ := strings.Cut(op, " ")
		seen[path] = true
	}
	var unreachable []string
	for path := range seen {
		// 路径参数在页面里是拼出来的：/settings/{key} → "/api/v1/settings/" + encodeURIComponent(...)
		prefix, _, _ := strings.Cut(path, "{")
		if !strings.Contains(html, prefix) {
			unreachable = append(unreachable, path)
		}
	}
	sort.Strings(unreachable)
	if len(unreachable) > 0 {
		t.Errorf("规格里有 %d 条路径在页面上没有任何出口：%v（要么接进页面，要么从规格里删掉）",
			len(unreachable), unreachable)
	}
}
