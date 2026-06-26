package convert

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spaolacci/murmur3"

	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

// TestEndToEnd_ConvertThenToQuery verifies the full pipeline:
// xray POC → neutron template YAML → load template → ToQuery().ToFOFA()
func TestEndToEnd_ConvertThenToQuery(t *testing.T) {
	xrayYAML := `
name: fingerprint-dingdian_network--08cms
detail:
  fingerprint:
    name: 08Cms
    cpe: dingdian_network:08cms
transport: http
rules:
  index_contains:
    expression: response.body_string.contains('/common/08cms.ico') ||
                response.body_string.contains("typeof(_08cms) != 'undefined'")
expression: index_contains()

# FOFA QUERY
# app="08CMS"
# http://jia.fengtai.tv/
`
	// Step 1: Convert
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	t.Logf("converted YAML:\n%s", string(out))

	// Step 2: Load as neutron template
	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal template: %v", err)
	}
	if err := tmpl.Compile(nil); err != nil {
		// Try compiling matchers directly
		for _, req := range tmpl.GetRequests() {
			(&req.Operators).Compile()
			req.CompiledOperators = &req.Operators
		}
	}

	// Step 3: ToQuery → fofa
	q := tmpl.ToQuery()
	fofa := q.ToFOFA()
	t.Logf("fofa query: %s", fofa.Query)

	// Verify: fofa-query should contain both the raw xray comment and matchers-generated query
	if !strings.Contains(fofa.Query, `app="08CMS"`) {
		t.Errorf("fofa query should contain raw xray comment app=\"08CMS\", got: %s", fofa.Query)
	}
	if !strings.Contains(fofa.Query, `body="/common/08cms.ico"`) {
		t.Errorf("fofa query should contain body= from matchers, got: %s", fofa.Query)
	}
}

func TestEndToEnd_OutputVariableFeedsNextRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(200)
			fmt.Fprint(w, `<script src="/static/app.abc123.js"></script>`)
		case "/static/app.abc123.js":
			w.WriteHeader(200)
			fmt.Fprint(w, "boot complete")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	xrayYAML := `
name: fingerprint-test--dynamic-output
detail:
  fingerprint:
    name: Dynamic Output
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("app.abc123.js")
    output:
      search: '"src=\"(?P<asset>/static/app\.[a-z0-9]+\.js)\"".submatch(response.body_string)'
      asset_path: search["asset"]
  fetch_asset:
    request:
      method: GET
      path: /{{asset_path}}
    expression: response.body_string.contains("boot complete")
expression: discover() && fetch_asset()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(string(out), `{{BaseURL}}/{{trim_prefix(asset_path, "/")}}`) {
		t.Fatalf("expected dynamic path to use xray BaseURL dedupe form:\n%s", string(out))
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile: %v\n%s", err, string(out))
	}
	result, err := tmpl.Execute(server.URL, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected converted template to match, got %#v\n%s", result, string(out))
	}
	if !strings.Contains(result.Request, "/static/app.abc123.js") {
		t.Fatalf("second request did not use extracted path:\n%s", result.Request)
	}
}

func TestEndToEnd_HunterQuery(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--hunter-example
detail:
  fingerprint:
    name: Hunter Example
    cpe: test:hunter
transport: http
rules:
  kw:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("test-keyword")
expression: kw()

# Hunter Query
# body="test-keyword"
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl.Compile(nil)
	for _, req := range tmpl.GetRequests() {
		(&req.Operators).Compile()
		req.CompiledOperators = &req.Operators
	}

	q := tmpl.ToQuery()
	hunter := q.ToHunter()
	t.Logf("hunter query: %s", hunter.Query)

	if !strings.Contains(hunter.Query, `body="test-keyword"`) {
		t.Errorf("hunter query missing, got: %s", hunter.Query)
	}
}

func TestEndToEnd_HeaderVariablesGenerateKeyedQueries(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--header-query
detail:
  fingerprint:
    name: Header Query
transport: http
rules:
  redirect:
    request:
      method: GET
      path: /
    expression: |-
      response.headers["Location"].contains("/login")
      && response.headers["Set-Cookie"].contains("JSESSIONID")
      && response.headers["WWW-Authenticate"].contains("Basic")
expression: redirect()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	t.Logf("converted:\n%s", out)

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl.Compile(nil)
	for _, req := range tmpl.GetRequests() {
		(&req.Operators).Compile()
		req.CompiledOperators = &req.Operators
	}

	fofa := tmpl.ToQuery().ToFOFA()
	for _, want := range []string{
		`header="location: /login"`,
		`header="set_cookie: JSESSIONID"`,
		`header="www_authenticate: Basic"`,
	} {
		if !strings.Contains(fofa.Query, want) {
			t.Fatalf("missing %s in fofa query %q\nconverted:\n%s", want, fofa.Query, out)
		}
	}
}

func TestEndToEnd_MultiRequestHistoryVariablesGenerateQueries(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--history-query
detail:
  fingerprint:
    name: History Query
transport: http
rules:
  first:
    request:
      method: GET
      path: /
    expression: |-
      response.status == 302
      && response.body_string.contains("redirect")
      && response.headers["Location"].contains("/login")
  second:
    request:
      method: GET
      path: /login
    expression: response.status == 200 && response.body_string.contains("ok")
expression: first() && second()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`status_code_1 == 302`,
		`contains(body_1, "redirect")`,
		`contains(all_headers_1, "location:")`,
		`contains(location_1, "/login")`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("converted template missing history variable %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"status_0", "status_code_0", "body_0", "headers_0"} {
		if strings.Contains(s, bad) {
			t.Fatalf("converted template should not emit zero-based history variable %q:\n%s", bad, s)
		}
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl.Compile(nil)
	for _, req := range tmpl.GetRequests() {
		(&req.Operators).Compile()
		req.CompiledOperators = &req.Operators
	}

	fofa := tmpl.ToQuery().ToFOFA()
	for _, want := range []string{
		`status_code="302"`,
		`body="redirect"`,
		`header="location: /login"`,
	} {
		if !strings.Contains(fofa.Query, want) {
			t.Fatalf("query missing %s in %q\nconverted:\n%s", want, fofa.Query, s)
		}
	}
}

func TestEndToEnd_ReqConditionLocationHistoryKeepsRedirectResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			fmt.Fprint(w, "one")
		case "/two":
			fmt.Fprint(w, "two")
		case "/jump":
			w.Header().Set("Location", "/resource/anonym.jsp")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, "jump")
		case "/resource/anonym.jsp":
			fmt.Fprint(w, "followed")
		case "/done":
			fmt.Fprint(w, "done")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	xrayYAML := `
name: fingerprint-test--history-location-redirect
detail:
  fingerprint:
    name: History Location Redirect
transport: http
rules:
  first:
    request:
      method: GET
      path: /one
    expression: response.status == 200
  second:
    request:
      method: GET
      path: /two
    expression: response.status == 200
  redirect:
    request:
      method: GET
      path: /jump
    expression: response.headers["Location"].contains("resource/anonym.jsp")
  final:
    request:
      method: GET
      path: /done
    expression: response.status == 200
expression: first() && second() && redirect() && final()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(string(out), `contains(location_3, "resource/anonym.jsp")`) {
		t.Fatalf("converted req-condition should reference the third response Location:\n%s", out)
	}
	if !strings.Contains(string(out), `contains(all_headers_3, "location:")`) {
		t.Fatalf("converted req-condition should guard the third response Location:\n%s", out)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	result, err := tmpl.Execute(server.URL, nil)
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected converted template to match using location_3 from the 302 response\n%s", out)
	}
}

func TestEndToEnd_StaticHeaderMissingDoesNotAbortAlternateBranch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("X-Test", "present")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "root")
		case "/ekp":
			fmt.Fprint(w, "CurrentUserId Com_Parameter StylePath")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	xrayYAML := `
name: fingerprint-test--missing-location-branch
detail:
  fingerprint:
    name: Missing Location Branch
transport: http
rules:
  redirect:
    request:
      method: GET
      path: /
      follow_redirects: false
    expression: response.headers["Location"].contains("resource/anonym.jsp")
  before:
    request:
      method: GET
      path: /
    expression: response.status in [401, 403, 404] || response.body_string.contains("/sys-ui/ui/style.css")
  ekp:
    request:
      method: GET
      path: /ekp
    expression: |-
      response.body_string.contains("CurrentUserId")
      && response.body_string.contains("Com_Parameter")
      && response.body_string.contains("StylePath")
expression: redirect() || (before() && ekp())
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !strings.Contains(string(out), `contains(all_headers_1, "location:")`) &&
		!strings.Contains(string(out), `contains(all_headers_2, "location:")`) {
		t.Fatalf("converted template should guard static Location access:\n%s", out)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	result, err := tmpl.Execute(server.URL, nil)
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected missing Location to evaluate false and continue to the body branch\n%s", out)
	}
}

func TestEndToEnd_GroupRulesSeparatesRedirectPolicies(t *testing.T) {
	var jumpHits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jump":
			jumpHits++
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			fmt.Fprint(w, "final-body")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	xrayYAML := `
name: fingerprint-test--same-path-redirect-policies
detail:
  fingerprint:
    name: Same Path Redirect Policies
transport: http
rules:
  final_body:
    request:
      method: GET
      path: /jump
    expression: response.body_string.contains("final-body")
  redirect_header:
    request:
      method: GET
      path: /jump
      follow_redirects: false
    expression: response.headers["Location"].contains("/final")
expression: final_body() && redirect_header()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(tmpl.GetRequests()) != 2 {
		t.Fatalf("same request shape with different redirect policies must stay split:\n%s", out)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	result, err := tmpl.Execute(server.URL, nil)
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected converted template to match both redirect policies\n%s", out)
	}
	if jumpHits != 2 {
		t.Fatalf("expected /jump to be requested once per redirect policy, got %d\n%s", jumpHits, out)
	}
}

func TestEndToEnd_NoComment(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--nocomment
detail:
  fingerprint:
    name: NoComment
    cpe: test:nocomment
transport: http
rules:
  kw:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body_string.contains("admin")
expression: kw()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl.Compile(nil)
	for _, req := range tmpl.GetRequests() {
		(&req.Operators).Compile()
		req.CompiledOperators = &req.Operators
	}

	q := tmpl.ToQuery()
	fofa := q.ToFOFA()
	t.Logf("fofa (from matchers only): %s", fofa.Query)

	// Should still produce a query from matchers
	if !strings.Contains(fofa.Query, `body="admin"`) {
		t.Errorf("fofa query should contain body=\"admin\" from matcher, got: %s", fofa.Query)
	}
	if !strings.Contains(fofa.Query, `status_code="200"`) {
		t.Errorf("fofa query should contain status_code from matcher, got: %s", fofa.Query)
	}
}

func TestXrayTemplatePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/admin", `{{BaseURL}}/admin`},
		{"/", `{{BaseURL}}/`},
		{"/druid/index.html", `{{BaseURL}}/druid/index.html`},
		{"", `{{BaseURL}}`},
		{"/{{trim_prefix(path, \"/\")}}", `{{BaseURL}}/{{trim_prefix(path, "/")}}`},
	}
	for _, tt := range tests {
		got := xrayTemplatePath(tt.path)
		if got != tt.want {
			t.Errorf("xrayTemplatePath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestEndToEnd_XrayPathUsesXappURLResolveSemantics(t *testing.T) {
	// xray/xapp paths resolve against the scan input like URL references. A
	// file-like input path resolves from the parent directory, while a
	// directory-like input path keeps that directory.
	xrayYAML := `
name: fingerprint-test--baseurl-path
detail:
  fingerprint:
    name: BaseURL Path Test
transport: http
rules:
  r0:
    request:
      method: GET
      path: /druid/index.html
    expression: response.status == 200 && response.body_string.contains("druid")
expression: r0()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `{{BaseURL}}/druid/index.html`) {
		t.Fatalf("expected xray resolver in converted path:\n%s", s)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl.Compile(nil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/druid/index.html":
			w.WriteHeader(200)
			fmt.Fprint(w, "druid dashboard")
			return
		case "/entry/druid/index.html":
			w.WriteHeader(200)
			fmt.Fprint(w, "druid dashboard")
			return
		}
		w.WriteHeader(404)
		fmt.Fprintf(w, "not found: %s", r.URL.Path)
	}))
	defer server.Close()

	result, err := tmpl.Execute(server.URL+"/entry", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected file-like input to match /druid/index.html")
	}

	result, err = tmpl.Execute(server.URL+"/entry/", nil)
	if err != nil {
		t.Fatalf("execute directory input: %v", err)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected directory-like input to match /entry/druid/index.html")
	}
}

// --- Tests merged from runtime_equivalence_test.go ---

func TestRuntimeEquivalence_OutputVariableChain(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-output
detail:
  fingerprint:
    name: Runtime Output
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("app.abc123.js")
    output:
      search: '"src=\"(?P<asset>/static/app\.[a-z0-9]+\.js)\"".submatch(response.body_string)'
      asset_path: search["asset"]
  fetch_asset:
    request:
      method: GET
      path: /{{asset_path}}
    expression: response.body_string.contains("boot complete")
expression: discover() && fetch_asset()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<script src="/static/app.abc123.js"></script>`)
		case "/static/app.abc123.js", "//static/app.abc123.js":
			fmt.Fprint(w, "boot complete")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_PayloadExpansion(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-payload
detail:
  fingerprint:
    name: Runtime Payload
transport: http
payloads:
  payloads:
    p0:
      value: '""'
    p1:
      value: '"admin/login"'
rules:
  r0:
    request:
      method: GET
      path: /{{value}}
    expression: response.body_string.contains("payload-hit")
expression: r0()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/login" {
			fmt.Fprint(w, "payload-hit")
			return
		}
		fmt.Fprint(w, "miss")
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_SetVariable(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-set
detail:
  fingerprint:
    name: Runtime Set
transport: http
set:
  randomPath: get404Path()
rules:
  r0:
    request:
      method: GET
      path: /{{randomPath}}
      follow_redirects: false
    expression: response.status == 404 && response.body_string.contains("synthetic 404")
expression: r0()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "synthetic 404")
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_RawOutputPathMayStartWithSlash(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-raw-output-path
detail:
  fingerprint:
    name: Runtime Raw Output Path
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("location")
    output:
      search: r'location="(?P<nextpath>[\/\w]+)'.submatch(response.body_string)
      nextpath: search["nextpath"]
  follow:
    request:
      method: GET
      path: /{{nextpath}}
    expression: response.body_string.contains("followed")
expression: discover() && follow()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `location="/next"`)
		case "/next", "//next":
			fmt.Fprint(w, "followed")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_FaviconHashDefaultPath(t *testing.T) {
	iconBody := []byte("equivalence-icon")
	iconHash := xrayRuntimeFaviconHash(iconBody)
	xray := fmt.Sprintf(`
name: fingerprint-test--runtime-favicon
detail:
  fingerprint:
    name: Runtime Favicon
transport: http
rules:
  favicon_hash:
    request:
      method: GET
      path: /
    expression: faviconHash(response.getIconContent()) == %s
expression: favicon_hash()
`, iconHash)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head></head></html>`)
		case "/favicon.ico":
			_, _ = w.Write(iconBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_MMH3IconInListAndFallback(t *testing.T) {
	iconBody := []byte("fallback-icon")
	iconHash := xrayRuntimeFaviconHash(iconBody)
	xray := fmt.Sprintf(`
name: fingerprint-test--runtime-mmh3-icon
detail:
  fingerprint:
    name: Runtime MMH3 Icon
transport: http
rules:
  favicon_hash:
    request:
      method: GET
      path: /
    expression: mmh3(icon(response)) in [111, %s, 222]
expression: favicon_hash()
`, iconHash)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body>no explicit icon</body></html>`)
		case "/favicon.ico":
			_, _ = w.Write(iconBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_BodyAndExplicitFaviconHash(t *testing.T) {
	iconBody := []byte("and-icon")
	iconHash := xrayRuntimeFaviconHash(iconBody)
	xray := fmt.Sprintf(`
name: fingerprint-test--runtime-body-and-favicon
detail:
  fingerprint:
    name: Runtime Body And Favicon
transport: http
rules:
  body_rule:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("home-marker")
  favicon_rule:
    request:
      method: GET
      path: /
    expression: faviconHash(response.getIconContent()) == %s
expression: body_rule() && favicon_rule()
`, iconHash)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "home-marker")
		case "/favicon.ico":
			_, _ = w.Write(iconBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_StringTitleAndLiteralContains(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-title-string
detail:
  fingerprint:
    name: Runtime Title String
transport: http
rules:
  title_rule:
    request:
      method: GET
      path: /
    expression: string(response.title).contains("Sindoh") && string(response.title).contains("Printer")
  literal_false:
    request:
      method: GET
      path: /
    expression: '"a".contains("b")'
expression: title_rule() || literal_false()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Sindoh Printer</title></head><body>title only</body></html>`)
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_CertSubjectAndTimeConvert(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-cert
detail:
  fingerprint:
    name: Runtime Cert
transport: http
rules:
  cert_rule:
    request:
      method: GET
      path: /
    expression: response.cert.subject.icontains("Acme Co") && timeConvert(response.cert.not_before, "2006-01-02 03:04:05").icontains("1970-01-01 12:00:00")
expression: cert_rule()
`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls ok")
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func assertRuntimeEquivalent(t *testing.T, xrayYAML, baseURL string) {
	t.Helper()

	xrayMatched, err := executeXrayRuntime(xrayYAML, baseURL)
	if err != nil {
		t.Fatalf("execute xray model: %v", err)
	}
	neutronMatched, converted := executeConvertedRuntime(t, xrayYAML, baseURL)
	if xrayMatched != neutronMatched {
		t.Fatalf("runtime inequivalent: xray=%v neutron=%v\nconverted:\n%s", xrayMatched, neutronMatched, converted)
	}
}

func executeConvertedRuntime(t *testing.T, xrayYAML, baseURL string) (bool, string) {
	t.Helper()

	converted, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var tmpl templates.Template
	if err := yaml.Unmarshal(converted, &tmpl); err != nil {
		t.Fatalf("unmarshal converted template: %v\n%s", err, converted)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile converted template: %v\n%s", err, converted)
	}
	result, err := tmpl.Execute(baseURL, nil)
	if err != nil {
		t.Fatalf("execute converted template: %v\n%s", err, converted)
	}
	return result != nil && result.Matched, string(converted)
}

func executeXrayRuntime(pocYAML, baseURL string) (bool, error) {
	var poc XrayPOC
	if err := yaml.Unmarshal([]byte(pocYAML), &poc); err != nil {
		return false, err
	}

	vars := deterministicXraySet(poc.Set)
	payloadRows := xrayPayloadRows(poc.Payloads)
	ruleResults := map[string]bool{}
	for _, ruleName := range orderedRuleNames(&poc) {
		rule := poc.Rules[ruleName]
		matched, err := executeXrayRule(baseURL, &rule, vars, payloadRows)
		if err != nil {
			return false, fmt.Errorf("%s: %v", ruleName, err)
		}
		ruleResults[ruleName] = matched
	}
	return evalTopExpr(poc.Expression, ruleResults), nil
}

func orderedRuleNames(poc *XrayPOC) []string {
	topExpr := parseTopExpression(poc.Expression)
	if topExpr == nil {
		return sortedKeys(poc.Rules)
	}
	seen := map[string]bool{}
	var names []string
	for _, name := range collectRuleNames(topExpr) {
		if seen[name] {
			continue
		}
		if _, ok := poc.Rules[name]; ok {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names
}

func executeXrayRule(baseURL string, rule *XrayRule, vars map[string]string, payloadRows []map[string]string) (bool, error) {
	if len(payloadRows) == 0 {
		payloadRows = []map[string]string{{}}
	}
	for _, payloads := range payloadRows {
		values := mergeStringMaps(vars, payloads)
		resp, err := requestXrayRule(baseURL, rule, values)
		if err != nil {
			return false, err
		}
		matched := xrayEval(rule.Expression, resp)
		if matched {
			applyXrayRuntimeOutput(rule.Output, resp, vars)
			return true, nil
		}
	}
	return false, nil
}

func requestXrayRule(baseURL string, rule *XrayRule, values map[string]string) (mockResponse, error) {
	method := rule.Request.Method
	if method == "" {
		method = http.MethodGet
	}
	reqPath := rule.Request.Path
	if reqPath == "" {
		reqPath = "/"
	}
	reqPath = replaceXrayPlaceholders(reqPath, values)
	target, err := joinURL(baseURL, reqPath)
	if err != nil {
		return mockResponse{}, err
	}
	body := replaceXrayPlaceholders(rule.Request.Body, values)
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		return mockResponse{}, err
	}
	for key, value := range rule.Request.Headers {
		req.Header.Set(key, replaceXrayPlaceholders(value, values))
	}

	client := &http.Client{}
	if strings.HasPrefix(target, "https://") {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	if !followRedirectsOrDefault(rule.Request.FollowRedirects) {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return mockResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	headers := map[string]string{}
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	if hash := xrayRuntimeFaviconHash(data); hash != "" {
		headers["__body_favicon_hash"] = hash
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		headers["__cert_subject"] = cert.Subject.String()
		headers["__cert_not_before"] = cert.NotBefore.Format("2006-01-02 03:04:05")
	}
	if resp.Request != nil && resp.Request.URL != nil {
		if hashes := xrayRuntimeIconHashes(client, resp.Request.URL, string(data), headers["__body_favicon_hash"]); len(hashes) > 0 {
			headers["__favicon_hash"] = strings.Join(hashes, "\n")
		}
	}
	return mockResponse{StatusCode: resp.StatusCode, Body: string(data), Headers: headers}, nil
}

func xrayRuntimeIconHashes(client *http.Client, base *url.URL, body, bodyHash string) []string {
	seen := map[string]struct{}{}
	hashes := map[string]struct{}{}
	addHash := func(hash string) {
		if hash != "" {
			hashes[hash] = struct{}{}
		}
	}
	for _, iconURL := range xrayRuntimeDiscoverIconURLs(base, body) {
		if _, ok := seen[iconURL]; ok {
			continue
		}
		seen[iconURL] = struct{}{}
		if iconURL == base.String() {
			addHash(bodyHash)
			continue
		}
		resp, err := client.Get(iconURL)
		if err != nil {
			continue
		}
		iconBody, _ := ioutil.ReadAll(resp.Body)
		_ = resp.Body.Close()
		addHash(xrayRuntimeFaviconHash(iconBody))
	}
	out := make([]string, 0, len(hashes))
	for hash := range hashes {
		out = append(out, hash)
	}
	sort.Strings(out)
	return out
}

func xrayRuntimeDiscoverIconURLs(base *url.URL, body string) []string {
	seen := map[string]struct{}{}
	var urls []string
	add := func(raw string) {
		raw = strings.TrimSpace(html.UnescapeString(raw))
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref).String()
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		urls = append(urls, resolved)
	}
	for _, tag := range xrayRuntimeLinkTagRE.FindAllString(body, -1) {
		rel := xrayRuntimeAttr(tag, "rel")
		if strings.Contains(strings.ToLower(rel), "icon") {
			add(xrayRuntimeAttr(tag, "href"))
		}
	}
	add("/favicon.ico")
	return urls
}

func xrayRuntimeAttr(tag, name string) string {
	for _, match := range xrayRuntimeAttrRE.FindAllStringSubmatch(tag, -1) {
		if len(match) >= 4 && strings.EqualFold(match[1], name) {
			if match[2] != "" {
				return match[2]
			}
			return match[3]
		}
	}
	return ""
}

func xrayRuntimeFaviconHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	var wrapped strings.Builder
	for len(encoded) > 76 {
		wrapped.WriteString(encoded[:76])
		wrapped.WriteByte('\n')
		encoded = encoded[76:]
	}
	wrapped.WriteString(encoded)
	wrapped.WriteByte('\n')

	hasher := murmur3.New32WithSeed(0)
	_, _ = hasher.Write([]byte(wrapped.String()))
	return fmt.Sprintf("%d", int32(hasher.Sum32()))
}

var (
	xrayRuntimeLinkTagRE = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	xrayRuntimeAttrRE    = regexp.MustCompile(`(?is)\b([a-z0-9_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

func deterministicXraySet(set map[string]interface{}) map[string]string {
	vars := map[string]string{}
	for key, raw := range set {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		switch {
		case strings.EqualFold(expr, "get404Path()"):
			vars[key] = "xray-equivalence-404"
		case strings.HasPrefix(expr, "randomLowercase("):
			vars[key] = "abcdefgh"
		case strings.HasPrefix(expr, "randomInt("):
			vars[key] = "123456"
		default:
			vars[key] = normalizeXrayScalar(expr)
		}
	}
	return vars
}

func xrayPayloadRows(root XrayPayloadRoot) []map[string]string {
	if len(root.Payloads) == 0 {
		return nil
	}
	rowKeys := make([]string, 0, len(root.Payloads))
	for key := range root.Payloads {
		rowKeys = append(rowKeys, key)
	}
	sortPayloadRows(rowKeys)

	rows := make([]map[string]string, 0, len(rowKeys))
	for _, rowKey := range rowKeys {
		row := map[string]string{}
		for name, value := range root.Payloads[rowKey] {
			row[name] = normalizeXrayScalar(fmt.Sprint(value))
		}
		rows = append(rows, row)
	}
	return rows
}

func applyXrayRuntimeOutput(output map[string]interface{}, resp mockResponse, vars map[string]string) {
	if len(output) == 0 {
		return
	}
	sources := map[string]map[string]string{}
	for name, raw := range output {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if specs := findSubmatchSpecs(expr); len(specs) > 0 {
			sources[name] = extractNamedGroups(specs[0], resp)
		}
	}

	for name, raw := range output {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if specs := findSubmatchSpecs(expr); len(specs) > 0 && specs[0].GroupName != "" {
			groups := extractNamedGroups(specs[0], resp)
			if value := groups[specs[0].GroupName]; value != "" {
				vars[name] = value
			}
			continue
		}
		if source, group, ok := outputSourceReference(expr); ok {
			if value := sources[source][group]; value != "" {
				vars[name] = value
			}
			continue
		}
	}
}

func extractNamedGroups(spec submatchSpec, resp mockResponse) map[string]string {
	result := map[string]string{}
	re, err := regexp.Compile(spec.Pattern)
	if err != nil {
		return result
	}
	corpus := responsePartForRuntime(spec.Part, resp)
	match := re.FindStringSubmatch(corpus)
	if len(match) == 0 {
		return result
	}
	for idx, name := range re.SubexpNames() {
		if idx > 0 && name != "" && idx < len(match) {
			result[name] = match[idx]
		}
	}
	return result
}

func responsePartForRuntime(part string, resp mockResponse) string {
	switch part {
	case "", "body":
		return resp.Body
	case "header", "all_headers":
		return buildRawHeader(resp.Headers)
	default:
		return getHeader(resp.Headers, part)
	}
}

func replaceXrayPlaceholders(s string, values map[string]string) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(match string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(match, "{{"), "}}")
		name = strings.TrimSpace(name)
		if value, ok := values[name]; ok {
			return value
		}
		return match
	})
}

func mergeStringMaps(left, right map[string]string) map[string]string {
	merged := map[string]string{}
	for key, value := range left {
		merged[key] = value
	}
	for key, value := range right {
		merged[key] = value
	}
	return merged
}

func joinURL(baseURL, reqPath string) (string, error) {
	if strings.HasPrefix(reqPath, "http://") || strings.HasPrefix(reqPath, "https://") {
		return reqPath, nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(reqPath, "/") {
		reqPath = "/" + reqPath
	}
	parsed.Path = reqPath
	parsed.RawQuery = ""
	return parsed.String(), nil
}
