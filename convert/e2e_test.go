package convert

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	if !strings.Contains(string(out), `{{BaseURL}}/{{xray_dedupe_path(BaseURL, asset_path)}}`) {
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
