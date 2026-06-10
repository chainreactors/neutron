package full

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
)

// matchJSON / matchXPath sit behind the same registration mechanism — make sure
// importing this submodule enables `type: json` / `type: xpath` matchers and
// that the basic positive/negative paths work end-to-end. The deeper truthy /
// AND-vs-OR semantics live in matcher.go itself; these tests are a smoke
// boundary against accidental regression at the registration layer.

func TestMatchJSON_Truthy(t *testing.T) {
	m := &operators.Matcher{Type: "json", JSON: []string{".ok"}}
	if err := m.CompileMatchers(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, hits := m.MatchWithHandler(`{"ok":true}`, nil)
	if !ok || len(hits) == 0 {
		t.Fatalf("expected truthy match, got ok=%v hits=%v", ok, hits)
	}
}

func TestMatchJSON_NoMatch(t *testing.T) {
	m := &operators.Matcher{Type: "json", JSON: []string{".missing"}}
	if err := m.CompileMatchers(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, _ := m.MatchWithHandler(`{"ok":true}`, nil)
	if ok {
		t.Fatalf("expected no match on missing field")
	}
}

func TestMatchXPath_HTML(t *testing.T) {
	m := &operators.Matcher{Type: "xpath", XPath: []string{"//title[text()='hello']"}}
	if err := m.CompileMatchers(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	ok, _ := m.MatchWithHandler(`<html><head><title>hello</title></head></html>`, nil)
	if !ok {
		t.Fatalf("expected xpath match")
	}
}
