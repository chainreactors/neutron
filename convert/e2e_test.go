package convert

import (
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
