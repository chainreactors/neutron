package full

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/chainreactors/neutron/operators"
)

// These tests cover the gojq-backed `json` extractor that this submodule
// registers on import. They lock in the behaviour the previous (deleted)
// mini-jq implementation guaranteed AND a few constructs the mini-jq
// implementation could not parse (pipes, select), proving the upgrade.

func TestExtractJSON_Basics(t *testing.T) {
	ext := &operators.Extractor{Type: "json", JSON: []string{".issuer_org[]", ".subject_cn", ".tls_version"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	corpus := `{"issuer_org":["Google Trust Services","Foo"],"subject_cn":"www.example.com","tls_version":"tls13"}`
	got := ext.ExtractWithHandler(corpus, nil)
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
	ext := &operators.Extractor{Type: "json", JSON: []string{".fingerprint_hash.sha256"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`{"fingerprint_hash":{"sha256":"abc","sha1":"def"}}`, nil)
	if _, ok := got["abc"]; !ok || len(got) != 1 {
		t.Fatalf("got %v want {abc}", keys(got))
	}
}

func TestExtractJSON_RootIterArray(t *testing.T) {
	ext := &operators.Extractor{Type: "json", JSON: []string{".[]"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`["a","b","c"]`, nil)
	if !reflect.DeepEqual(keys(got), []string{"a", "b", "c"}) {
		t.Fatalf("got %v", keys(got))
	}
}

func TestExtractJSON_MissingField(t *testing.T) {
	// gojq emits `null` for a missing field (different from the previous
	// mini-jq, which produced no results). The extractor stringifies `null`
	// via JSONScalarToString → ToString(nil) → "", so the result is one
	// empty-string entry. Lock that in — the same shape nuclei sees.
	ext := &operators.Extractor{Type: "json", JSON: []string{".nope"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`{"yes":"hi"}`, nil)
	if _, ok := got[""]; !ok || len(got) != 1 {
		t.Fatalf("expected {\"\"}, got %v", keys(got))
	}
}

func TestExtractJSON_MissingFieldEmptySuppressed(t *testing.T) {
	// And the gojq-native escape hatch: `// empty` collapses the absent case
	// to no results, matching what mini-jq did by default.
	ext := &operators.Extractor{Type: "json", JSON: []string{".nope // empty"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`{"yes":"hi"}`, nil)
	if len(got) != 0 {
		t.Fatalf("expected 0 results, got %v", keys(got))
	}
}

func TestExtractJSON_ObjectValue(t *testing.T) {
	// When the leaf is a non-scalar, it's re-marshaled to JSON.
	ext := &operators.Extractor{Type: "json", JSON: []string{".fingerprint_hash"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`{"fingerprint_hash":{"md5":"x"}}`, nil)
	want := `{"md5":"x"}`
	if _, ok := got[want]; !ok {
		t.Fatalf("expected %s, got %v", want, keys(got))
	}
}

// The whole reason we switched from mini-jq to gojq: these expressions used to
// be rejected at compile time as "unsupported jq construct". Now they must work.
func TestExtractJSON_GojqSuperset(t *testing.T) {
	cases := []struct {
		name  string
		expr  string
		input string
		want  []string
	}{
		{
			name:  "pipe",
			expr:  ".foo | .bar",
			input: `{"foo":{"bar":"hit"}}`,
			want:  []string{"hit"},
		},
		{
			name:  "select",
			expr:  `.items[] | select(.id == "x") | .name`,
			input: `{"items":[{"id":"x","name":"yes"},{"id":"y","name":"no"}]}`,
			want:  []string{"yes"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ext := &operators.Extractor{Type: "json", JSON: []string{tc.expr}}
			if err := ext.CompileExtractors(); err != nil {
				t.Fatalf("compile %q: %v", tc.expr, err)
			}
			got := ext.ExtractWithHandler(tc.input, nil)
			if !reflect.DeepEqual(keys(got), tc.want) {
				t.Fatalf("%s: got %v want %v", tc.name, keys(got), tc.want)
			}
		})
	}
}

func TestCompileExtractors_BadJSONExpr(t *testing.T) {
	ext := &operators.Extractor{Type: "json", JSON: []string{".foo |"}} // dangling pipe — gojq rejects this
	err := ext.CompileExtractors()
	if err == nil {
		t.Fatal("expected error on malformed jq expression")
	}
	if !strings.Contains(err.Error(), "json") {
		t.Fatalf("error should mention json compile failure, got: %v", err)
	}
}

// --- xpath ---

func TestExtractXPath_HTML(t *testing.T) {
	ext := &operators.Extractor{Type: "xpath", XPath: []string{"//title"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`<html><head><title>hello</title></head></html>`, nil)
	if _, ok := got["hello"]; !ok {
		t.Fatalf("expected 'hello', got %v", keys(got))
	}
}

func TestExtractXPath_HTMLAttribute(t *testing.T) {
	ext := &operators.Extractor{Type: "xpath", XPath: []string{"//a"}, Attribute: "href"}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`<html><body><a href="https://example.com">x</a></body></html>`, nil)
	if _, ok := got["https://example.com"]; !ok {
		t.Fatalf("expected attr 'https://example.com', got %v", keys(got))
	}
}

func TestExtractXPath_XML(t *testing.T) {
	ext := &operators.Extractor{Type: "xpath", XPath: []string{"//user/name"}}
	if err := ext.CompileExtractors(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ext.ExtractWithHandler(`<?xml version="1.0"?><root><user><name>alice</name></user></root>`, nil)
	if _, ok := got["alice"]; !ok {
		t.Fatalf("expected 'alice', got %v", keys(got))
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
