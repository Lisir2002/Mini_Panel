package nginx

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CORS is the twenty-first slice of M2. The operator supplies a structured
// policy — allowed origins, methods, request headers, credentials and a
// preflight cache lifetime — and the panel renders fixed server-level
// add_header directives plus one server-level OPTIONS short-circuit. Nothing
// here owns `location /`, so CORS coexists with static, rewrite, proxy (both
// forms), redirects and every other site feature. Two boundaries are stated
// rather than hidden: while CORS is on, OPTIONS requests are answered locally
// with 204 and never reach the upstream, and the panel does not hide CORS
// headers an upstream may send on its own (duplicates are the operator's to
// resolve by disabling one side).

const (
	maxCorsOrigins = 10
	maxCorsHeaders = 20
	maxCorsMaxAge  = 86400
)

// corsHeaderTokenRe is the RFC 7230 token shape for header names; anything
// outside it could break out of the quoted add_header value.
var corsHeaderTokenRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// corsMethods is the closed method vocabulary. OPTIONS is always allowed in
// the rendered Allow-Methods line because the preflight short-circuit answers
// it; the operator picks the data methods.
var corsMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"DELETE": true, "PATCH": true, "OPTIONS": true,
}

// CorsSettings is one site's cross-origin policy. Origins is either exactly
// ["*"] or a list of exact scheme://host[:port] origins; an empty list means
// CORS is off. Methods defaults to GET/HEAD/POST when empty; Headers empty
// means the preflight's Access-Control-Request-Headers is reflected back.
type CorsSettings struct {
	Origins     []string `json:"origins"`
	Methods     []string `json:"methods,omitempty"`
	Headers     []string `json:"headers,omitempty"`
	Credentials bool     `json:"credentials,omitempty"`
	MaxAge      int      `json:"max_age,omitempty"`
}

// normalizeCors validates a request-shaped policy and returns the canonical
// form stored in the marker and rendered into nginx. An empty origin list is
// the clear operation and is always allowed; everything else is ignored then.
func normalizeCors(in CorsSettings) (CorsSettings, error) {
	out := CorsSettings{}
	seen := map[string]bool{}
	for i, raw := range in.Origins {
		o := strings.TrimSpace(raw)
		if o == "" {
			return CorsSettings{}, fmt.Errorf("%w：第 %d 个来源为空", ErrInvalid, i+1)
		}
		if o == "*" {
			if len(in.Origins) != 1 {
				return CorsSettings{}, fmt.Errorf("%w：通配符 * 不能与其它来源混用", ErrInvalid)
			}
		} else {
			u, err := parseUpstreamURL(o, "CORS 来源")
			if err != nil {
				return CorsSettings{}, err
			}
			if u.path != "" {
				return CorsSettings{}, fmt.Errorf("%w：CORS 来源 %q 不能带路径，只接受 scheme://主机[:端口]", ErrInvalid, o)
			}
			o = u.String()
		}
		if seen[o] {
			return CorsSettings{}, fmt.Errorf("%w：CORS 来源 %q 重复", ErrInvalid, o)
		}
		seen[o] = true
		out.Origins = append(out.Origins, o)
	}
	if len(out.Origins) == 0 {
		return CorsSettings{}, nil
	}
	if len(out.Origins) > maxCorsOrigins {
		return CorsSettings{}, fmt.Errorf("%w：CORS 来源最多 %d 个", ErrInvalid, maxCorsOrigins)
	}
	sort.Strings(out.Origins)
	if in.Credentials && seen["*"] {
		return CorsSettings{}, fmt.Errorf("%w：浏览器禁止 Access-Control-Allow-Origin 为 * 时携带凭据，请列出具体来源", ErrInvalid)
	}
	methods := in.Methods
	if len(methods) == 0 {
		methods = []string{"GET", "HEAD", "POST"}
	}
	mseen := map[string]bool{}
	for _, m := range methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !corsMethods[m] {
			return CorsSettings{}, fmt.Errorf("%w：CORS 方法 %q 不在支持列表（GET/HEAD/POST/PUT/DELETE/PATCH/OPTIONS）", ErrInvalid, m)
		}
		if !mseen[m] {
			mseen[m] = true
			out.Methods = append(out.Methods, m)
		}
	}
	sort.Strings(out.Methods)
	hseen := map[string]bool{}
	for i, h := range in.Headers {
		h = strings.TrimSpace(h)
		if !corsHeaderTokenRe.MatchString(h) {
			return CorsSettings{}, fmt.Errorf("%w：第 %d 个允许头 %q 不是合法的 header 名", ErrInvalid, i+1, h)
		}
		if !hseen[h] {
			hseen[h] = true
			out.Headers = append(out.Headers, h)
		}
	}
	if len(out.Headers) > maxCorsHeaders {
		return CorsSettings{}, fmt.Errorf("%w：允许的请求头最多 %d 个", ErrInvalid, maxCorsHeaders)
	}
	sort.Strings(out.Headers)
	if in.MaxAge < 0 || in.MaxAge > maxCorsMaxAge {
		return CorsSettings{}, fmt.Errorf("%w：预检缓存时间必须在 0-%d 秒之间", ErrInvalid, maxCorsMaxAge)
	}
	out.MaxAge = in.MaxAge
	out.Credentials = in.Credentials
	return out, nil
}

// corsLines renders the fixed server-level directives for a normalized
// policy. For an explicit origin list the request's Origin is matched with
// one `if` per origin and echoed back through a panel-named variable, so an
// unlisted origin gets no Access-Control-Allow-Origin header at all (nginx
// skips add_header with an empty value) — no http-level map is needed, which
// keeps the feature available on hosts without a wildcard include.
func corsLines(c CorsSettings) string {
	var b strings.Builder
	b.WriteString("    # CORS: fixed policy rendered by Mini Panel.\n")
	if c.Origins[0] == "*" {
		b.WriteString("    add_header Access-Control-Allow-Origin \"*\" always;\n")
	} else {
		b.WriteString("    set $mp_cors_origin \"\";\n")
		for _, o := range c.Origins {
			b.WriteString("    if ($http_origin = \"" + o + "\") { set $mp_cors_origin \"" + o + "\"; }\n")
		}
		b.WriteString("    add_header Access-Control-Allow-Origin $mp_cors_origin always;\n")
		b.WriteString("    add_header Vary \"Origin\" always;\n")
	}
	b.WriteString("    add_header Access-Control-Allow-Methods \"" + strings.Join(c.Methods, ", ") + "\" always;\n")
	if len(c.Headers) > 0 {
		b.WriteString("    add_header Access-Control-Allow-Headers \"" + strings.Join(c.Headers, ", ") + "\" always;\n")
	} else {
		// Reflect the preflight's requested headers. The value is a request
		// header, which cannot carry raw newlines, so it stays one token list.
		b.WriteString("    add_header Access-Control-Allow-Headers $http_access_control_request_headers always;\n")
	}
	if c.Credentials {
		b.WriteString("    add_header Access-Control-Allow-Credentials \"true\" always;\n")
	}
	if c.MaxAge > 0 {
		fmt.Fprintf(&b, "    add_header Access-Control-Max-Age %d always;\n", c.MaxAge)
	}
	// The preflight short-circuit. It has no add_header of its own, so the
	// server-level headers above are inherited into the 204 response.
	b.WriteString("    if ($request_method = OPTIONS) { return 204; }\n")
	return b.String()
}

// corsFromMarker copies the already-validated policy out of a marker payload.
func corsFromMarker(p markerPayload) *CorsSettings {
	if p.Cors == nil || len(p.Cors.Origins) == 0 {
		return nil
	}
	c := *p.Cors
	return &c
}

// SetCors replaces or clears the site's CORS policy. Clearing is always
// allowed. The directives are server-level and do not own `location /`, so
// the policy coexists with every other site feature; while it is on, OPTIONS
// requests are answered locally with 204 instead of reaching the upstream.
func (m *Manager) SetCors(name string, in CorsSettings) (Site, error) {
	if err := ValidateName(name); err != nil {
		return Site{}, err
	}
	c, err := normalizeCors(in)
	if err != nil {
		return Site{}, err
	}
	site, ok := m.readSite(FileName(name))
	if !ok {
		return Site{}, ErrNotFound
	}
	if len(c.Origins) == 0 {
		site.Cors = nil
	} else {
		site.Cors = &c
	}
	if err := m.applyConfig(site.ConfigPath, render(site)); err != nil {
		return Site{}, err
	}
	return site, nil
}
