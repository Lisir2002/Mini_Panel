package docsync

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// 这个文件把 README 与 docs/*.md 里的 `path:line` 指针对着仓库真文件核对。
//
// 存在的理由不是"文档写错了不好看"，而是本项目把每条说法都标了复核方式：读者会照着
// grep 去核。指针一旦漂到别处，复核本身就变成假话——比不写更糟。M0/M1 两次全量核对
// 各逮到一批漂移行号（含一处倒着写的区间、一处引用了仓库里根本不存在的测试名），
// 所以这里把核对固化成会失败的测试，而不是"改代码时记得改文档"。
//
// 三条断言，从弱到强：
//  1. 指针指向的文件存在、行号没越过文件末尾、区间不是倒着的；
//  2. 指针后面反引号里若写了符号名（`Foo()`、`var trustProxy`），那个符号必须真的落在
//     所指的行附近，否则报出它现在真正在第几行；
//  3. 文档点名的 `TestXxx` 必须存在于某个 .go 测试文件；文档引用的 `minipanel <命令>`
//     必须能被 dispatch 且出现在 usage 里，`--flag` 必须出现在 usage 里。

// root 从本文件自己的路径回溯到仓库根，这样断言不依赖 go test 的工作目录。
func root(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 失败，无法定位仓库根目录")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
}

func readLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读取 %s: %v", p, err)
	}
	return strings.Split(string(b), "\n")
}

// docFiles 是这条检查负责的文案范围。
func docFiles(t *testing.T) []string {
	t.Helper()
	r := root(t)
	out := []string{filepath.Join(r, "README.md")}
	des, err := os.ReadDir(filepath.Join(r, "docs"))
	if err != nil {
		t.Fatalf("读取 docs/: %v", err)
	}
	for _, d := range des {
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".md") {
			out = append(out, filepath.Join(r, "docs", d.Name()))
		}
	}
	sort.Strings(out)
	return out
}

var (
	// citedPath: 任意非空白、非冒号的片段以扩展名结尾，后面跟 :行 或 :行-行。
	// Makefile 没有扩展名，但它同样是指针的常见目标（README 讲 ldflags 时引用它），
	// 所以单独列进交替里。
	citedPath = regexp.MustCompile(`((?:[^\s:，、()（）` + "`" + `]+\.(?:go|vue|yaml|yml|md|json|mod|sh|ts|js|mjs|css)|Makefile)):(\d+)(?:-(\d+))?`)
	// anyLineRef: 同一句里后出现的 `:342`、`:175-183`，它继承前面那个文件名。
	anyLineRef = regexp.MustCompile(`:[0-9]+(?:-[0-9]+)?`)
	// ident 从指针所在反引号里挑出看起来像 Go 符号的片段。
	ident = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{2,}`)
	// testName 保留紧跟的 `*`：文档用 `TestSessionEndpoints*` 指一整组测试。
	testName = regexp.MustCompile(`(Test[A-Z][A-Za-z0-9_]*)(\*?)`)
	// cliCommand picks `minipanel doctor` out of README.
	cliCommand = regexp.MustCompile(`minipanel ([a-z][a-z0-9-]*)`)
)

// noise 列出现在指针反引号里、但不指代 Go 符号的词。把它们算进断言会让检查变成
// 对措辞的绑架，而不是对落点的核对。
var noise = map[string]bool{
	"api": true, "app": true, "css": true, "doc": true, "docs": true, "fmt": true,
	"go": true, "golang": true, "http": true, "https": true, "json": true, "js": true,
	"linux": true, "mjs": true, "mod": true, "php": true, "sqlite": true, "sql": true,
	"src": true, "tls": true, "ts": true, "uri": true, "url": true, "vue": true,
	"yaml": true, "yml": true, "sh": true, "md": true, "tsx": true, "dist": true,
	"web": true, "webui": true, "cmd": true, "internal": true, "platform": true,
	"openapi": true, "panel": true, "minipanel": true, "true": true, "false": true,
	"nil": true, "err": true, "func": true, "const": true, "type": true, "struct": true,
	"map": true, "get": true, "put": true, "post": true, "del": true, "var": true,
	"int": true, "str": true, "ok": true, "jsonp": true, "utf": true, "html": true,
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// resolveFile 让 `main.go:87` 这种"上下文里已经知道是哪个包"的写法也能被核对：
// 先按仓库根解析，解析不到再按文件名走一遍，取路径最短的命中，保证报错可复现。
func resolveFile(r, name string, cache map[string]string) (string, bool) {
	if p, ok := cache[name]; ok {
		return p, p != ""
	}
	hit := ""
	if p := filepath.Join(r, name); fileExists(p) {
		hit = p
	} else {
		base := filepath.Base(name)
		_ = filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			switch filepath.Base(filepath.Dir(p)) {
			case ".git", "node_modules", "bin", "data", "dist":
				return nil
			}
			if d.Name() == base && (hit == "" || len(p) < len(hit)) {
				hit = p
			}
			return nil
		})
	}
	cache[name] = hit
	return hit, hit != ""
}

// nextCarry 决定看完这一行之后，裸指针该继承哪个文件。
//
// 文档里的长条目是折着写的：一条以 "`capabilities_test.go:14 TestX`（Deny / Allow /"
// 开头、下一行接着写 "`:84 declaredFeatures()`"。第二行开头没有文件名，但它显然还指着
// 同一个文件；不看这种写法就会漏掉附录里一半的锚点。
//
// 这份方便用句子边界收着：空行、以句号/叹号/问号收尾的行、markdown 表格行（以 | 收尾）
// 都会清掉 carry。于是继承只跨越"这句还没说完"的换行，不会从上一段或上一行表格偷到
// 一个不相干的文件上——偷错文件比漏查更糟，因为它会报出一个看起来很合理的假错误。
func nextCarry(carry, line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasSuffix(t, "|") {
		return ""
	}
	if r, _ := utf8.DecodeLastRuneInString(t); r == '。' || r == '！' || r == '？' {
		return ""
	}
	for _, m := range citedPath.FindAllStringSubmatch(line, -1) {
		carry = m[1]
	}
	return carry
}

type citation struct {
	path       string
	start, end int
	tail       string
}

// citationsInLine 返回一行里所有指针。裸 `:342` 归给**它前面**最近出现的那个文件——
// 文档就是这么写的（"`system.go:78-83` `:108-116`、`config.go:1-7` `:29`"），
// 检查若看不懂这种写法会漏掉一半，若归错文件还会假报错。
// carry 是上一行留下的文件：附录里的长条目会折行，折下去的那半行开头就是一个裸指针，
// 它继承的显然是上一条里的文件，不是"找不到落点"。空行会清掉 carry，不会让归属跨过段落。
func citationsInLine(line, carry string) []citation {
	var out []citation
	type span struct {
		from, to int
		path     string
	}
	var spans []span
	for _, m := range citedPath.FindAllStringSubmatchIndex(line, -1) {
		p := line[m[2]:m[3]]
		s, _ := strconv.Atoi(line[m[4]:m[5]])
		e := s
		if m[6] >= 0 {
			e, _ = strconv.Atoi(line[m[6]:m[7]])
		}
		spans = append(spans, span{from: m[0], to: m[1], path: p})
		out = append(out, citation{path: p, start: s, end: e, tail: spanTail(line, m[1])})
	}
	// owner returns the file a bare pointer inherits: the last explicit citation
	// that starts before it, or — when this line has none yet, because the entry
	// wrapped — the file the previous line of the same paragraph left behind.
	// Without either the pointer is prose, not a pointer, and gets skipped.
	owner := func(pos int) string {
		last := carry
		for _, s := range spans {
			if s.from < pos {
				last = s.path
			}
		}
		return last
	}
	inSpan := func(pos int) bool {
		for _, s := range spans {
			if pos >= s.from && pos < s.to {
				return true
			}
		}
		return false
	}
	for _, m := range anyLineRef.FindAllStringIndex(line, -1) {
		if inSpan(m[0]) {
			continue
		}
		if notALineRef(line, m[0]) {
			continue
		}
		path := owner(m[0])
		if path == "" {
			continue
		}
		txt := strings.TrimPrefix(line[m[0]:m[1]], ":")
		sStr, eStr, _ := strings.Cut(txt, "-")
		s, err := strconv.Atoi(sStr)
		if err != nil {
			continue
		}
		e := s
		if eStr != "" {
			if n, err := strconv.Atoi(eStr); err == nil {
				e = n
			}
		}
		out = append(out, citation{path: path, start: s, end: e, tail: spanTail(line, m[1])})
	}
	return out
}

// spanTail 是指针之后、同一个反引号之内的那段文字——符号锚点就写在那里。
func spanTail(line string, end int) string {
	if end <= 0 || end >= len(line) {
		return ""
	}
	n := strings.IndexByte(line[end:], '`')
	if n < 0 {
		n = 60
	}
	if end+n > len(line) {
		n = len(line) - end
	}
	return line[end : end+n]
}

func windowOf(body []string, from, to int) string {
	lo := from - 3
	if lo < 0 {
		lo = 0
	}
	hi := to + 2
	if hi > len(body) {
		hi = len(body)
	}
	return strings.Join(body[lo:hi], "\n")
}

// notALineRef 判断冒号前面那串字符是不是"地址"而不是"文件:行"：
// `0.0.0.0:29080`、`https://服务器IP:29080/<入口>` 里的冒号是端口分隔符。
// 不排掉它们的话，文档里每一个默认端口都会被读成"第 29080 行"，这条检查会因为
// 太容易报错误而失去意义。判定范围只到本段的定界符（空格、反引号、括号、顿号、
// 逗号、分号、竖线、冒号）为止，所以真正的裸指针（`（`:114`）`）不受影响。
func notALineRef(line string, pos int) bool {
	if pos == 0 {
		return false
	}
	if c := line[pos-1]; c >= '0' && c <= '9' {
		return true
	}
	for i := pos; i > 0; {
		r, size := utf8.DecodeLastRuneInString(line[:i])
		i -= size
		switch r {
		case ' ', '\t', '`', '|', '[', '（', '(', '、', '，', '；', ':', '：', '。':
			return false
		case '.', '/', '-':
			return true // 地址、URL 或带连字符的主机名的一部分
		}
	}
	return false
}

// orphanRefs 返回的是"这一行有裸 `:行`，但既没有同行的文件名可继承、上一行也已经收尾"
// 的那些原文。它们不是错误，是检查自愿放弃的部分——放弃多少、放弃在哪必须打印出来，
// 否则这条检查的覆盖面会悄悄缩水，而 Logf 里那行数字看着还挺好看。
func orphanRefs(line, carry string) []string {
	idx := citedPath.FindAllStringIndex(line, -1)
	var out []string
	for _, m := range anyLineRef.FindAllStringIndex(line, -1) {
		if notALineRef(line, m[0]) {
			continue // 地址与端口的冒号
		}
		inSpan, before := false, false
		for _, s := range idx {
			if m[0] >= s[0] && m[0] < s[1] {
				inSpan = true
			}
			if s[0] < m[0] {
				before = true
			}
		}
		if inSpan || before || carry != "" {
			continue
		}
		out = append(out, line[m[0]:m[1]])
	}
	return out
}

// TestCitationsPointInsideRealFiles 是最弱的一条：文件在、行号在文件里、区间没写反。
// `capabilities.go:202-136` 在附录里躺了很久没人看见，因为没有任何 Go 代码读过那个数字。
func TestCitationsPointInsideRealFiles(t *testing.T) {
	r := root(t)
	files, cache := map[string][]string{}, map[string]string{}
	total, bad := 0, 0
	var orphans []string
	for _, doc := range docFiles(t) {
		carry := ""
		for i, line := range readLines(t, doc) {
			for _, c := range citationsInLine(line, carry) {
				total++
				target, ok := resolveFile(r, c.path, cache)
				if !ok {
					t.Errorf("%s:%d: 指针 %s 指向的文件不存在", rel(r, doc), i+1, c.path)
					bad++
					continue
				}
				body, seen := files[target]
				if !seen {
					body = readLines(t, target)
					files[target] = body
				}
				switch {
				case c.start == 0:
					t.Errorf("%s:%d: %s 的指针没写成行号", rel(r, doc), i+1, c.path)
					bad++
				case c.start > len(body):
					t.Errorf("%s:%d: %s:%d 越过文件末尾（该文件共 %d 行）",
						rel(r, doc), i+1, rel(r, target), c.start, len(body))
					bad++
				case c.end > len(body):
					t.Errorf("%s:%d: %s:%d-%d 越过文件末尾（该文件共 %d 行）",
						rel(r, doc), i+1, rel(r, target), c.start, c.end, len(body))
					bad++
				case c.end < c.start:
					t.Errorf("%s:%d: %s:%d-%d 区间写反了", rel(r, doc), i+1, rel(r, target), c.start, c.end)
					bad++
				default:
					// 落在空行或纯收尾符号上，同样是漂了的证据：一个指针应该指着
					// 能读出意思的那一行，而不是 `}`。
					line := strings.TrimSpace(body[c.start-1])
					if isHollow(line) {
						t.Errorf("%s:%d: %s:%d 指的是第 %d 行，那里是 %q——空行或收尾括号不算落点",
							rel(r, doc), i+1, rel(r, target), c.start, c.start, line)
						bad++
					}
				}
			}
			for _, o := range orphanRefs(line, carry) {
				orphans = append(orphans, fmt.Sprintf("%s:%d 的裸 %s", rel(r, doc), i+1, o))
			}
			carry = nextCarry(carry, line)
		}
	}
	where := "无"
	if len(orphans) > 0 {
		where = strings.Join(orphans, "；")
	}
	t.Logf("核对了 %d 个行号指针，其中 %d 个找不到或越界；%d 处裸 `:行` 无人认领（前一行已经收尾，检查不去猜归属）：%s",
		total, bad, len(orphans), where)
}

// isHollow 判断一个源文件的行是否"什么都没承载"：空行，或者整行只剩收尾的括号、
// 花括号、引号、分号、逗号与注释。指针落在这种行上，说明代码挪过而文档没跟上。
func isHollow(line string) bool {
	if line == "" {
		return true
	}
	for _, r := range line {
		switch r {
		case '}', ')', ']', ';', ',', '"', '`', '/', '*', ' ':
		default:
			return false
		}
	}
	return true
}

// TestAnchoredCitationsSayWhatTheyClaim 是真正对着漂移的那条：写了符号名的指针，
// 符号必须就在所指行上。
func TestAnchoredCitationsSayWhatTheyClaim(t *testing.T) {
	r := root(t)
	files, cache := map[string][]string{}, map[string]string{}
	checked := 0
	for _, doc := range docFiles(t) {
		carry := ""
		for i, line := range readLines(t, doc) {
			for _, c := range citationsInLine(line, carry) {
				var want []string
				seen := map[string]bool{}
				for _, tok := range ident.FindAllString(c.tail, -1) {
					if noise[strings.ToLower(tok)] || seen[tok] {
						continue
					}
					seen[tok] = true
					want = append(want, tok)
				}
				if len(want) == 0 {
					continue
				}
				target, ok := resolveFile(r, c.path, cache)
				if !ok {
					continue // 上一条测试已经报过
				}
				body, exist := files[target]
				if !exist {
					body = readLines(t, target)
					files[target] = body
				}
				win := windowOf(body, c.start, c.end)
				var missing, where []string
				for _, name := range want {
					if strings.Contains(win, name) {
						continue
					}
					missing = append(missing, name)
					hits := []int{}
					for n, l := range body {
						if strings.Contains(l, name) {
							hits = append(hits, n+1)
							if len(hits) == 3 {
								break
							}
						}
					}
					if len(hits) == 0 {
						where = append(where, fmt.Sprintf("%s 在该文件里不存在", name))
					} else {
						where = append(where, fmt.Sprintf("%s 现在在第 %v 行", name, hits))
					}
				}
				if len(missing) == 0 {
					checked++
					continue
				}
				t.Errorf("%s:%d: 指针 %s:%d-%d 里没有 %v（%s）",
					rel(r, doc), i+1, rel(r, target), c.start, c.end, missing, strings.Join(where, "；"))
			}
			carry = nextCarry(carry, line)
		}
	}
	if checked == 0 {
		t.Fatal("一个带符号名的指针都没核对到——要么正则失配，要么文档不再写锚点，这条检查就该算失败")
	}
	t.Logf("%d 个带符号锚点的指针全部落在所指行上", checked)
}

// TestNamedTestsAndCommandsExist 管的是行号管不了的那一类：文档点名的东西压根不存在。
// `TestDenyAndAllowAreSymmetric` 曾在三份文档里被当作 check-honesty 的一部分引用，
// 而仓库里从来没有这个测试——行号核对对它完全无感，因为写错的是名字而不是数字。
//
// 名字只要求"在某个 .go 文件里作为标识符出现"：文档里的 `TestConfig`/`Reload`/`Restart`
// 是 `WebServerCtl` 的方法名（M2 的接口形状），不是测试函数，用 `func Test…(` 去要求
// 它们会把设计文档误判成说谎。
//
// 命令存在性只对着 README.md 检查。README 是"照着走能不能跑通"的那份文档，它写出的
// `minipanel <命令>` 必须今天就能执行；docs/功能设计.md 是设计空间，里面有
// `minipanel audit export` 这类明确标着 M4 的计划项，把计划说成谎报没有任何意义。
func TestNamedTestsAndCommandsExist(t *testing.T) {
	r := root(t)
	var src strings.Builder
	_ = filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch filepath.Base(filepath.Dir(p)) {
		case ".git", "node_modules", "bin", "data", "dist":
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			src.Write(b)
			src.WriteByte('\n')
		}
		return nil
	})
	usage, err := os.ReadFile(filepath.Join(r, "cmd", "minipanel", "main.go"))
	if err != nil {
		t.Fatalf("读取 cmd/minipanel/main.go: %v", err)
	}
	code, help := src.String(), string(usage)

	tests := map[string]bool{}
	for _, doc := range docFiles(t) {
		body := strings.Join(readLines(t, doc), "\n")
		for _, m := range testName.FindAllStringSubmatch(body, -1) {
			if m[2] == "*" { // `TestSessionEndpoints*` 是一组测试的写法，不是一个名字
				continue
			}
			tests[m[1]] = true
		}
	}
	for name := range tests {
		if !strings.Contains(code, name) {
			t.Errorf("文档点名的 %s 在仓库里找不到：要么把它写出来，要么改掉说法", name)
		}
	}

	readme := filepath.Join(r, "README.md")
	body := strings.Join(readLines(t, readme), "\n")
	cmds := map[string]bool{}
	for _, m := range cliCommand.FindAllStringSubmatch(body, -1) {
		cmds[m[1]] = true
	}
	for name := range cmds {
		if !strings.Contains(help, `case "`+name+`"`) {
			t.Errorf("README 引用了 `minipanel %s`，但 dispatch 的 switch 里没有这个分支", name)
		}
		if !strings.Contains(help, name) {
			t.Errorf("`minipanel %s` 没出现在 usage 文本里——帮助文档漏了它", name)
		}
	}
	t.Logf("文档点名 %d 个标识符、README 点名 %d 个子命令，全部存在", len(tests), len(cmds))
}

func rel(r, p string) string {
	x, err := filepath.Rel(r, p)
	if err != nil {
		return p
	}
	return x
}
