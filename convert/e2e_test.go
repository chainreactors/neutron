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
	if strings.Contains(string(out), "{{RootURL}}/{{asset_path}}") {
		t.Fatalf("dynamic path with leading-slash extractor should not keep an extra slash:\n%s", string(out))
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
		{"/admin", "{{RootURL}}/admin"},
		{"/", "{{RootURL}}/"},
		{"/druid/index.html", "{{RootURL}}/druid/index.html"},
		{"", "{{BaseURL}}"},
		{"/{{trim_prefix(path, \"/\")}}", "{{RootURL}}/{{trim_prefix(path, \"/\")}}"},
	}
	for _, tt := range tests {
		got := xrayTemplatePath(tt.path)
		if got != tt.want {
			t.Errorf("xrayTemplatePath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestEndToEnd_RootURLPreventsDoubledPath(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--rooturl-path
detail:
  fingerprint:
    name: RootURL Path Test
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
	if !strings.Contains(s, "{{RootURL}}/druid/index.html") {
		t.Fatalf("expected RootURL in converted path:\n%s", s)
	}
	if strings.Contains(s, "{{BaseURL}}/druid") {
		t.Fatalf("should not use BaseURL for absolute xray path:\n%s", s)
	}

	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tmpl.Compile(nil)

	// Simulate target with path: http://host/druid/
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/druid/index.html" {
			w.WriteHeader(200)
			fmt.Fprint(w, "druid dashboard")
			return
		}
		w.WriteHeader(404)
		fmt.Fprintf(w, "not found: %s", r.URL.Path)
	}))
	defer server.Close()

	// Pass target WITH path — RootURL strips it, so template hits /druid/index.html not /druid/druid/index.html
	result, err := tmpl.Execute(server.URL+"/druid/", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result == nil || !result.Matched {
		t.Fatalf("expected match — RootURL should prevent /druid/druid/ doubling")
	}
}
