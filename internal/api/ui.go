package api

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

// serveUI answers every non-API route from the embedded front end.
//
// The panel is a single-page app: unknown paths under the entrance resolve to
// index.html and the router in the browser takes over. This is the same shape
// BaoTa uses (one index.html shell behind 127 Flask routes), except that here
// the API and the UI are visibly separate namespaces: anything under /api/ that
// does not exist answers as a JSON 404 instead of being handed HTML, which is
// what makes a broken endpoint diagnosable rather than mysterious.
func (s *Server) serveUI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, "method", "该路径仅支持 GET")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusNotFound, "not_found", "接口不存在，请核对 openapi/panel.yaml")
			return
		}
		assets := embeddedUI()
		if assets == nil {
			// `go build` of the API alone (webui/dist empty) still runs, and says so.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = io.WriteString(w, "Mini Panel API 正在运行。前端资源未编译：请执行 make web 后重新构建。\n")
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if fi, err := fs.Stat(assets, name); err != nil || fi.IsDir() {
			name = "index.html"
		}
		http.ServeFileFS(w, r, assets, name)
	})
}

// handleNotFound answers an unmatched API route. A UI path never lands here
// because the "/*" handler above already serves index.html for it, so the only
// way to reach this is a real endpoint typo.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotFound, "not_found", "接口不存在，请核对 openapi/panel.yaml")
}

func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持 "+r.Method+" 方法")
}

// chiParam reads a path parameter without every handler importing chi.
func chiParam(r *http.Request, key string) string { return chi.URLParam(r, key) }
