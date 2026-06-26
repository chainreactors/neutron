package convert

import (
	"strings"
	"testing"
)

// Regression for the newline-normalisation fix in xrayLex. A control byte
// inside a string literal must round-trip — not be collapsed to a space by a
// blanket input-wide Replace — so needsHexDecodeLiteral can wrap it in
// hex_decode(). Without this a literal newline would silently match the letters
// "a b" instead of the real byte.
func TestLexerPreservesControlByteInStringLiteral(t *testing.T) {
	for _, in := range []string{
		`response.body.contains("a` + "\n" + `b")`, // real LF inside the literal
		`response.body.contains("a` + "\r" + `b")`, // real CR inside the literal
	} {
		node, err := ParseToAST(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		got := node.String()
		if !strings.Contains(got, "hex_decode(") {
			t.Fatalf("literal with control byte must be hex-wrapped; got %s", got)
		}
		if strings.Contains(got, "a b") {
			t.Fatalf("control byte was collapsed to a space (regression); got %s", got)
		}
	}
}

// Newlines between tokens (whitespace separators) must still be skipped, and
// must not bleed into the produced DSL.
func TestLexerSkipsNewlinesBetweenTokens(t *testing.T) {
	// "a" == "b" with a newline between the two operands
	in := `response.status == 200` + "\n" + `&& response.body.contains("ok")`
	node, err := ParseToAST(in)
	if err != nil {
		t.Fatalf("parse multiline input: %v", err)
	}
	got := node.String()
	if !strings.Contains(got, "200") || !strings.Contains(got, `"ok"`) {
		t.Fatalf("multiline input was not lexed correctly; got %s", got)
	}
}
