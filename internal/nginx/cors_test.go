package nginx

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// CORS is a fixed server-level policy: add_header lines plus one OPTIONS
// short-circuit. These tests pin validation, exact rendering, marker
// round-trips, coexistence with every location / owner, rollback, marker
// rejection and ownership.

func TestCorsIsValidated(t *testing.T) {
	got, err := normalizeCors(CorsSettings{
		Origins: []string{"https://b.example.com", " http://a.example.com:8080 "},
		Methods: []string{"post", "GET", "get"},
		Headers: []string{"X-Token", "Content-Type", "X-Token"},
		MaxAge:  600,
	})
	if err != nil {
		t.Fatalf("normalizeCors: %v", err)
	}
	if strings.Join(got.Origins, "|") != "http://a.example.com:8080|https://b.example.com" {
		t.Errorf("origins = %v", got.Origins)
	}
	if strings.Join(got.Methods, "|") != "GET|POST" {
		t.Errorf("methods = %v", got.Methods)
	}
	if strings.Join(got.Headers, "|") != "Content-Type|X-Token" {
		t.Errorf("headers = %v", got.Headers)
	}
	// Empty methods default to the safe read/write trio.
	if got, err := normalizeCors(CorsSettings{Origins: []string{"*"}}); err != nil ||
		strings.Join(got.Methods, ",") != "GET,HEAD,POST" {
		t.Errorf("default methods = %v, %v", got, err)
	}
	// Empty origins is the clear operation; everything else is ignored.
	if got, err := normalizeCors(CorsSettings{Methods: []string{"BOGUS"}, MaxAge: -1}); err != nil || len(got.Origins) != 0 {
		t.Errorf("clear = %+v, %v", got, err)
	}

	invalid := []CorsSettings{
		{Origins: []string{"*", "https://a.example.com"}},
		{Origins: []string{"https://a.example.com", "*"}},
		{Origins: []string{"https://a.example.com/path"}},
		{Origins: []string{"https://a.example.com", "https://a.example.com"}},
		{Origins: []string{"ftp://a.example.com"}},
		{Origins: []string{"https://a.example.com;return 500"}},
		{Origins: []string{""}},
		{Origins: []string{"*"}, Credentials: true},
		{Origins: []string{"*"}, Methods: []string{"TRACE"}},
		{Origins: []string{"*"}, Headers: []string{"X-Bad;Name"}},
		{Origins: []string{"*"}, Headers: []string{"X Bad"}},
		{Origins: []string{"*"}, MaxAge: -1},
		{Origins: []string{"*"}, MaxAge: maxCorsMaxAge + 1},
	}
	for _, c := range invalid {
		if _, err := normalizeCors(c); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeCors(%+v) err = %v, want ErrInvalid", c, err)
		}
	}
	tooManyOrigins := make([]string, maxCorsOrigins+1)
	for i := range tooManyOrigins {
		tooManyOrigins[i] = "https://a" + strconv.Itoa(i) + ".example.com"
	}
	if _, err := normalizeCors(CorsSettings{Origins: tooManyOrigins}); !errors.Is(err, ErrInvalid) {
		t.Errorf("over-long origins err = %v, want ErrInvalid", err)
	}
	tooManyHeaders := make([]string, maxCorsHeaders+1)
	for i := range tooManyHeaders {
		tooManyHeaders[i] = "X-H" + strconv.Itoa(i)
	}
	if _, err := normalizeCors(CorsSettings{Origins: []string{"*"}, Headers: tooManyHeaders}); !errors.Is(err, ErrInvalid) {
		t.Errorf("over-long headers err = %v, want ErrInvalid", err)
	}
}

func TestSetCorsRendersAndRoundTrips(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "api", Domains: []string{"api.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec.cmds = nil
	site, err := m.SetCors("api", CorsSettings{
		Origins:     []string{"https://app.example.com", "http://localhost:5173"},
		Methods:     []string{"GET", "POST", "PUT", "DELETE"},
		Headers:     []string{"Content-Type", "Authorization"},
		Credentials: true,
		MaxAge:      600,
	})
	if err != nil {
		t.Fatalf("SetCors: %v", err)
	}
	if want := []string{"nginx -t", "nginx -s reload"}; strings.Join(rec.cmds, "|") != strings.Join(want, "|") {
		t.Errorf("command order = %v, want %v", rec.cmds, want)
	}
	if site.Cors == nil || len(site.Cors.Origins) != 2 || !site.Cors.Credentials {
		t.Fatalf("returned site = %+v", site)
	}
	body, err := os.ReadFile(m.Layout.ConfigPath("api"))
	if err != nil {
		t.Fatalf("vhost not written: %v", err)
	}
	for _, want := range []string{
		"    set $mp_cors_origin \"\";\n",
		"    if ($http_origin = \"https://app.example.com\") { set $mp_cors_origin \"https://app.example.com\"; }\n",
		"    if ($http_origin = \"http://localhost:5173\") { set $mp_cors_origin \"http://localhost:5173\"; }\n",
		"    add_header Access-Control-Allow-Origin $mp_cors_origin always;\n",
		"    add_header Vary \"Origin\" always;\n",
		"    add_header Access-Control-Allow-Methods \"DELETE, GET, POST, PUT\" always;\n",
		"    add_header Access-Control-Allow-Headers \"Authorization, Content-Type\" always;\n",
		"    add_header Access-Control-Allow-Credentials \"true\" always;\n",
		"    add_header Access-Control-Max-Age 600 always;\n",
		"    if ($request_method = OPTIONS) { return 204; }\n",
		`"cors":{"origins":["http://localhost:5173","https://app.example.com"]`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("vhost missing %q\n%s", want, body)
		}
	}
	list, err := m.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v", list, err)
	}
	if list[0].Cors == nil || len(list[0].Cors.Origins) != 2 || list[0].Cors.MaxAge != 600 || !list[0].Cors.Credentials {
		t.Errorf("marker round-trip = %+v", list[0].Cors)
	}

	// Wildcard renders the fixed star and no origin matching; empty headers
	// reflect the preflight's requested headers.
	if _, err := m.SetCors("api", CorsSettings{Origins: []string{"*"}}); err != nil {
		t.Fatalf("wildcard: %v", err)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("api"))
	for _, want := range []string{
		"    add_header Access-Control-Allow-Origin \"*\" always;\n",
		"    add_header Access-Control-Allow-Headers $http_access_control_request_headers always;\n",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("wildcard vhost missing %q\n%s", want, body)
		}
	}
	for _, absent := range []string{"$mp_cors_origin", "Access-Control-Allow-Credentials", "Access-Control-Max-Age"} {
		if strings.Contains(string(body), absent) {
			t.Errorf("wildcard vhost still contains %q", absent)
		}
	}

	// Clearing removes every CORS line and is a real write.
	rec.cmds = nil
	site, err = m.SetCors("api", CorsSettings{})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if site.Cors != nil {
		t.Errorf("clear left policy: %+v", site.Cors)
	}
	body, _ = os.ReadFile(m.Layout.ConfigPath("api"))
	if strings.Contains(string(body), "Access-Control") || strings.Contains(string(body), "$mp_cors_origin") {
		t.Errorf("clear left CORS lines:\n%s", body)
	}
	if len(rec.cmds) != 2 {
		t.Errorf("clear commands = %v, want -t + reload", rec.cmds)
	}
}

func TestCorsCoexistsWithLocationOwners(t *testing.T) {
	m, _ := newLimitsManager(t)
	if _, err := m.Create(Spec{Name: "app", Domains: []string{"app.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	policy := CorsSettings{Origins: []string{"https://front.example.com"}}
	// Every location / owner accepts CORS on top, and CORS accepts them.
	if _, err := m.SetProxy("app", "http://127.0.0.1:3000", false); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if _, err := m.SetCors("app", policy); err != nil {
		t.Fatalf("CORS on proxy: %v", err)
	}
	body, _ := os.ReadFile(m.Layout.ConfigPath("app"))
	if !strings.Contains(string(body), "proxy_pass http://127.0.0.1:3000;") || !strings.Contains(string(body), "Access-Control-Allow-Origin") {
		t.Errorf("proxy + CORS missing from:\n%s", body)
	}
	if _, err := m.SetProxyUpstreams("app", []ProxyUpstream{{Target: "http://127.0.0.1:3000"}}, "", false); err != nil {
		t.Fatalf("SetProxyUpstreams with CORS: %v", err)
	}
	if _, err := m.SetProxy("app", "", false); err != nil {
		t.Fatalf("clear proxy: %v", err)
	}
	if _, err := m.SetRedirect("app", "https://new.example.com", 301, true); err != nil {
		t.Fatalf("SetRedirect with CORS: %v", err)
	}
	if _, err := m.SetRedirect("app", "", 0, false); err != nil {
		t.Fatalf("clear redirect: %v", err)
	}
	if _, err := m.SetRewrite("app", "spa"); err != nil {
		t.Fatalf("SetRewrite with CORS: %v", err)
	}
	if _, err := m.SetHotlink("app", true, true); err != nil {
		t.Fatalf("SetHotlink with CORS: %v", err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].Cors == nil {
		t.Fatalf("policy lost through handovers: %v %v", list, err)
	}
}

func TestSetCorsRollsBack(t *testing.T) {
	m, rec := newTestManager(t)
	if _, err := m.Create(Spec{Name: "api", Domains: []string{"api.example.com"}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	before, err := os.ReadFile(m.Layout.ConfigPath("api"))
	if err != nil {
		t.Fatal(err)
	}
	rec.failOn = "-t"
	if _, err := m.SetCors("api", CorsSettings{Origins: []string{"*"}}); err == nil {
		t.Fatal("SetCors succeeded despite nginx -t failure")
	}
	after, _ := os.ReadFile(m.Layout.ConfigPath("api"))
	if string(before) != string(after) {
		t.Error("failed SetCors did not restore the exact bytes")
	}
}

func TestMarkerRejectsBadCors(t *testing.T) {
	bad := []string{
		`"cors":{"origins":["*","https://a.example.com"]}`,
		`"cors":{"origins":["https://a.example.com/path"]}`,
		`"cors":{"origins":["*"],"credentials":true}`,
		`"cors":{"origins":["*"],"methods":["TRACE"]}`,
		`"cors":{"origins":["*"],"headers":["X;Bad"]}`,
		`"cors":{"origins":["*"],"max_age":999999}`,
		`"cors":{"origins":["https://a.example.com","https://a.example.com"]}`,
	}
	for _, frag := range bad {
		body := "# minipanel-site: {" + `"name":"api","domains":["api.example.com"],"root":"/www/api",` + frag + "}\nserver {}\n"
		if _, ok := parseMarker(body); ok {
			t.Errorf("parseMarker accepted bad cors %s", frag)
		}
	}
	// An empty-origin cors object normalizes to off, not to a foreign file.
	body := "# minipanel-site: {" + `"name":"api","domains":["api.example.com"],"root":"/www/api","cors":{"origins":[]}}` + "\nserver {}\n"
	if p, ok := parseMarker(body); !ok || p.Cors != nil {
		t.Errorf("empty cors should normalize to off, got ok=%v cors=%+v", ok, p.Cors)
	}
}

func TestSetCorsOwnershipAndName(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.SetCors("Bad Name", CorsSettings{Origins: []string{"*"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name err = %v, want ErrInvalid", err)
	}
	if _, err := m.SetCors("missing", CorsSettings{Origins: []string{"*"}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site err = %v, want ErrNotFound", err)
	}
	foreign := m.Layout.ConfigPath("other")
	content := "server { listen 80; server_name other.example.com; }\n"
	if err := os.WriteFile(foreign, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetCors("other", CorsSettings{Origins: []string{"*"}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("foreign vhost err = %v, want ErrNotFound", err)
	}
	after, _ := os.ReadFile(foreign)
	if string(after) != content {
		t.Error("foreign vhost was modified")
	}
}
