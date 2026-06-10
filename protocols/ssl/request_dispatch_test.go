package ssl

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
)

// These tests pin the operator dispatch wiring introduced when ssl moved to the
// shared protocols.MakeDefaultMatchFunc / MakeDefaultExtractFunc with an
// injected PartResolver. They deliberately do NOT exercise gojq — that lives in
// the operators/full submodule — they assert that ssl routes json/xpath (any
// non-builtin type) through the registered handler against the resolved part,
// which is the exact path that was silently missing before (a json extractor
// fell through to `return nil`). A fake handler stands in for operators/full so
// the test stays stdlib-only and runs in the go1.11 main-module CI.

func TestSSLExtractRoutesJSONToHandlerAgainstResponse(t *testing.T) {
	var gotCorpus string
	var called bool
	operators.RegisterExtractorType("json", operators.JSONExtractor, nil,
		func(e *operators.Extractor, corpus string, _ map[string]interface{}) map[string]struct{} {
			called = true
			gotCorpus = corpus
			return map[string]struct{}{corpus: {}}
		})

	ext := &operators.Extractor{Type: "json", JSON: []string{".issuer_org[]"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile extractor: %v", err)
	}

	r := &Request{}
	data := map[string]interface{}{"response": `{"issuer_org":["ACME"]}`}
	out := r.Extract(data, ext)

	if !called {
		t.Fatal("json extractor did not reach the registered handler (dispatch regression)")
	}
	if gotCorpus != `{"issuer_org":["ACME"]}` {
		t.Fatalf("handler got wrong part corpus: %q (expected the response JSON)", gotCorpus)
	}
	if _, ok := out[`{"issuer_org":["ACME"]}`]; !ok {
		t.Fatalf("extract result not propagated: %v", out)
	}
}

func TestSSLExtractFoldsBodyAndAllToResponse(t *testing.T) {
	var corpora []string
	operators.RegisterExtractorType("json", operators.JSONExtractor, nil,
		func(e *operators.Extractor, corpus string, _ map[string]interface{}) map[string]struct{} {
			corpora = append(corpora, corpus)
			return nil
		})

	data := map[string]interface{}{"response": "RESP"}
	r := &Request{}
	for _, part := range []string{"", "body", "all"} {
		ext := &operators.Extractor{Type: "json", Part: part, JSON: []string{"."}}
		if err := ext.CompileExtractors(); err != nil {
			t.Fatalf("compile (part=%q): %v", part, err)
		}
		r.Extract(data, ext)
	}

	if len(corpora) != 3 {
		t.Fatalf("expected 3 handler calls, got %d", len(corpora))
	}
	for i, c := range corpora {
		if c != "RESP" {
			t.Fatalf("part fold failed at call %d: corpus=%q (expected response 'RESP')", i, c)
		}
	}
}

func TestSSLMatchRoutesJSONToHandler(t *testing.T) {
	var called bool
	operators.RegisterMatcherType("json", operators.JSONMatcher, nil,
		func(m *operators.Matcher, corpus string, _ map[string]interface{}) (bool, []string) {
			called = true
			if corpus != "RESP" {
				t.Errorf("matcher got corpus %q, expected response 'RESP'", corpus)
			}
			return true, []string{corpus}
		})

	m := &operators.Matcher{Type: "json", JSON: []string{".ok"}}
	if err := m.CompileMatchers(); err != nil {
		t.Fatalf("compile matcher: %v", err)
	}

	r := &Request{}
	data := map[string]interface{}{"response": "RESP"}
	ok, snip := r.Match(data, m)
	if !called {
		t.Fatal("json matcher did not reach the registered handler (dispatch regression)")
	}
	if !ok || len(snip) == 0 {
		t.Fatalf("match result not propagated: ok=%v snip=%v", ok, snip)
	}
}
