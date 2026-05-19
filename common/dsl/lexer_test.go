package dsl

import (
	"testing"
)

func TestLexSimple(t *testing.T) {
	tokens, err := Lex(`contains(body, "test") && status_code == 200`)
	if err != nil {
		t.Fatal(err)
	}

	expected := []struct {
		typ TokenType
		val string
	}{
		{TIdent, "contains"},
		{TLParen, "("},
		{TIdent, "body"},
		{TComma, ","},
		{TString, "test"},
		{TRParen, ")"},
		{TAnd, "&&"},
		{TIdent, "status_code"},
		{TEq, "=="},
		{TNumber, "200"},
		{TEOF, ""},
	}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(tokens), tokens)
	}
	for i, e := range expected {
		if tokens[i].Type != e.typ || tokens[i].Value != e.val {
			t.Errorf("token[%d]: expected {%d %q}, got {%d %q}", i, e.typ, e.val, tokens[i].Type, tokens[i].Value)
		}
	}
}

func TestLexSingleQuote(t *testing.T) {
	tokens, err := Lex(`contains(body, 'hello world')`)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[4].Type != TString || tokens[4].Value != "hello world" {
		t.Errorf("expected string 'hello world', got %v", tokens[4])
	}
}

func TestLexOperators(t *testing.T) {
	tokens, err := Lex(`a != b || c >= d && e <= f`)
	if err != nil {
		t.Fatal(err)
	}
	types := []TokenType{TIdent, TNeq, TIdent, TOr, TIdent, TGte, TIdent, TAnd, TIdent, TLte, TIdent, TEOF}
	if len(tokens) != len(types) {
		t.Fatalf("expected %d tokens, got %d", len(types), len(tokens))
	}
	for i, typ := range types {
		if tokens[i].Type != typ {
			t.Errorf("token[%d]: expected type %d, got %d (%q)", i, typ, tokens[i].Type, tokens[i].Value)
		}
	}
}

func TestLexBool(t *testing.T) {
	tokens, err := Lex(`true && false`)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Type != TBool || tokens[0].Value != "true" {
		t.Errorf("expected bool true, got %v", tokens[0])
	}
	if tokens[2].Type != TBool || tokens[2].Value != "false" {
		t.Errorf("expected bool false, got %v", tokens[2])
	}
}

func TestLexEscapedString(t *testing.T) {
	tokens, err := Lex(`"hello\"world"`)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Value != `hello"world` {
		t.Errorf(`expected hello"world, got %q`, tokens[0].Value)
	}
}

func TestLexNot(t *testing.T) {
	tokens, err := Lex(`!contains(body, "x")`)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Type != TNot {
		t.Errorf("expected TNot, got %d", tokens[0].Type)
	}
}
