package operators

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestCompileJSONPath_Accepts(t *testing.T) {
	cases := []struct {
		expr  string
		steps []jsonStep
	}{
		{".", nil},
		{".foo", []jsonStep{{kind: fieldStep, name: "foo"}}},
		{".foo.bar", []jsonStep{{kind: fieldStep, name: "foo"}, {kind: fieldStep, name: "bar"}}},
		{".foo[]", []jsonStep{{kind: fieldStep, name: "foo"}, {kind: iterStep}}},
		{".[]", []jsonStep{{kind: iterStep}}},
		{".a.b[]", []jsonStep{{kind: fieldStep, name: "a"}, {kind: fieldStep, name: "b"}, {kind: iterStep}}},
		{".issuer_org[]", []jsonStep{{kind: fieldStep, name: "issuer_org"}, {kind: iterStep}}},
	}
	for _, tc := range cases {
		p, err := compileJSONPath(tc.expr)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", tc.expr, err)
		}
		if !reflect.DeepEqual(p.steps, tc.steps) {
			t.Fatalf("%q: steps = %+v want %+v", tc.expr, p.steps, tc.steps)
		}
	}
}

func TestCompileJSONPath_Rejects(t *testing.T) {
	// Each entry MUST fail at compile time with a message naming the construct
	// — we want users to know exactly which syntax we can't handle, not to get
	// silent no-results.
	cases := []string{
		"",
		"foo",                  // missing leading dot
		".[",                   // unterminated iterator
		".foo[",                // unterminated iterator after field
		".foo | .bar",          // pipe
		".foo, .bar",           // comma
		".items | select(.id)", // select()
		".items | map(.id)",    // map()
		".a + .b",              // arithmetic
		".a?",                  // optional
	}
	for _, expr := range cases {
		if _, err := compileJSONPath(expr); err == nil {
			t.Fatalf("%q: expected error, got nil", expr)
		}
	}
}

func TestExtractJSON_Basics(t *testing.T) {
	ext := &Extractor{Type: "json", JSON: []string{".issuer_org[]", ".subject_cn", ".tls_version"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	corpus := `{"issuer_org":["Google Trust Services","Foo"],"subject_cn":"www.example.com","tls_version":"tls13"}`
	got := ext.ExtractJSON(corpus)
	want := map[string]struct{}{
		"Google Trust Services": {},
		"Foo":                   {},
		"www.example.com":       {},
		"tls13":                 {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", keys(got), keys(want))
	}
}

func TestExtractJSON_Nested(t *testing.T) {
	ext := &Extractor{Type: "json", JSON: []string{".fingerprint_hash.sha256"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractJSON(`{"fingerprint_hash":{"sha256":"abc","sha1":"def"}}`)
	if _, ok := got["abc"]; !ok || len(got) != 1 {
		t.Fatalf("got %v want {abc}", keys(got))
	}
}

func TestExtractJSON_RootIterArray(t *testing.T) {
	ext := &Extractor{Type: "json", JSON: []string{".[]"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractJSON(`["a","b","c"]`)
	if !reflect.DeepEqual(keys(got), []string{"a", "b", "c"}) {
		t.Fatalf("got %v", keys(got))
	}
}

func TestExtractJSON_MissingField(t *testing.T) {
	ext := &Extractor{Type: "json", JSON: []string{".nope"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractJSON(`{"yes":"hi"}`)
	if len(got) != 0 {
		t.Fatalf("expected 0 results, got %v", keys(got))
	}
}

func TestExtractJSON_ObjectValue(t *testing.T) {
	// When the leaf is a non-scalar, it's re-marshaled to JSON.
	ext := &Extractor{Type: "json", JSON: []string{".fingerprint_hash"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractJSON(`{"fingerprint_hash":{"md5":"x"}}`)
	want := `{"md5":"x"}`
	if _, ok := got[want]; !ok {
		t.Fatalf("expected %s, got %v", want, keys(got))
	}
}

func TestCompileExtractors_UnknownTypeIsClear(t *testing.T) {
	// Pre-registration we returned "unknown extractor type specified: json".
	// Now json is supported; this test guards against accidentally removing
	// the mapping again.
	ext := &Extractor{Type: "json", JSON: []string{".foo"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("json extractor must compile, got %v", err)
	}
}

func TestCompileExtractors_BadJSONExpr(t *testing.T) {
	ext := &Extractor{Type: "json", JSON: []string{".foo | .bar"}}
	err := ext.CompileExtractors()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported jq construct") {
		t.Fatalf("error message should name the unsupported construct, got: %v", err)
	}
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
