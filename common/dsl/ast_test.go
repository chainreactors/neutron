package dsl

import (
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

func TestNodeStringKeepsDateLikeStringsAsStrings(t *testing.T) {
	node := Call("contains",
		Variable("body"),
		Literal("1970-01-01 12:00:00"),
	)
	expr := node.String()
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
