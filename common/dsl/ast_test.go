package dsl

import (
	"strings"
	"testing"

	"github.com/Knetic/govaluate"
)

func TestNodeStringEscapesSingleQuotesInStringLiterals(t *testing.T) {
	node := Call("contains",
		Variable("body"),
		Literal(`{{ 'Common.Title' | translate }}`),
	)
	expr := node.String()
	if expr != `contains(body, "{{ \'Common.Title\' | translate }}")` {
		t.Fatalf("unexpected expression: %s", expr)
	}
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, HelperFunctions())
	if err != nil {
		t.Fatalf("compile generated DSL: %v", err)
	}
	got, err := compiled.Evaluate(map[string]interface{}{
		"body": `prefix {{ 'Common.Title' | translate }} suffix`,
	})
	if err != nil {
		t.Fatalf("evaluate generated DSL: %v", err)
	}
	if got != true {
		t.Fatalf("expected match, got %#v", got)
	}
}

// Date-like literals must go through hex_decode, not a plain quoted literal.
// govaluate does not error on "1970-01-01 12:00:00" — it silently returns the
// wrong boolean (verified: the quoted form evaluates to false even when body
// contains it). This also locks in that the old per-rune concat() form was
// replaced by the same hex_decode path used for control bytes / invalid UTF-8.
func TestNodeStringHexWrapsDateLikeLiterals(t *testing.T) {
	node := Call("contains",
		Variable("body"),
		Literal("1970-01-01 12:00:00"),
	)
	expr := node.String()
	if !strings.Contains(expr, "hex_decode(") {
		t.Fatalf("date-like literal must be hex-wrapped, got: %s", expr)
	}
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, HelperFunctions())
	if err != nil {
		t.Fatalf("compile generated DSL: %v", err)
	}
	got, err := compiled.Evaluate(map[string]interface{}{
		"body": "prefix 1970-01-01 12:00:00 suffix",
	})
	if err != nil {
		t.Fatalf("evaluate generated DSL: %v", err)
	}
	if got != true {
		t.Fatalf("expected match, got %#v from %s", got, expr)
	}
}

func TestNodeStringUsesHexDecodeForBinaryStringLiterals(t *testing.T) {
	node := Call("starts_with",
		Variable("body"),
		Literal("PK\x03\x04"),
	)
	expr := node.String()
	if expr != `starts_with(body, hex_decode("504b0304"))` {
		t.Fatalf("unexpected expression: %s", expr)
	}
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, HelperFunctions())
	if err != nil {
		t.Fatalf("compile generated DSL: %v", err)
	}
	got, err := compiled.Evaluate(map[string]interface{}{
		"body": "PK\x03\x04zip body",
	})
	if err != nil {
		t.Fatalf("evaluate generated DSL: %v", err)
	}
	if got != true {
		t.Fatalf("expected match, got %#v from %s", got, expr)
	}
}

// Control bytes including standard whitespace (\n \r \t) MUST be emitted via
// hex_decode, not as a quoted "...\n..." literal. govaluate only honours \" as
// an escape; \n \t \r silently drop the backslash, so a quoted form would match
// the wrong bytes. This locks that invariant so it is not "optimised" away.
func TestNodeStringHexWrapsControlBytesAndWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"newline", "line1\nline2"},
		{"tab", "a\tb"},
		{"carriage_return", "a\rb"},
		{"null", "a\x00b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expr := Call("contains", Variable("body"), Literal(tc.value)).String()
			if !strings.Contains(expr, "hex_decode(") {
				t.Fatalf("control byte %q must be hex-wrapped, got: %s", tc.value, expr)
			}
			compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, HelperFunctions())
			if err != nil {
				t.Fatalf("compile generated DSL: %v", err)
			}
			got, err := compiled.Evaluate(map[string]interface{}{"body": tc.value})
			if err != nil {
				t.Fatalf("evaluate generated DSL: %v", err)
			}
			if got != true {
				t.Fatalf("expected match, got %#v from %s", got, expr)
			}
		})
	}
}
