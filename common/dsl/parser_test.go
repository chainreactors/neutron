package dsl

import "testing"

func TestParseContains(t *testing.T) {
	node, err := Parse(`contains(body, "test")`)
	if err != nil {
		t.Fatal(err)
	}
	if node.Type != NodeCall || node.FuncName != "contains" {
		t.Fatalf("expected call to contains, got %s", node)
	}
	if len(node.Children) != 2 {
		t.Fatalf("expected 2 args, got %d", len(node.Children))
	}
	if node.Children[0].Value != "body" {
		t.Errorf("expected arg0=body, got %v", node.Children[0].Value)
	}
	if node.Children[1].Value != "test" {
		t.Errorf("expected arg1=test, got %v", node.Children[1].Value)
	}
}

func TestParseCompound(t *testing.T) {
	node, err := Parse(`contains(body, "admin") && status_code == 200`)
	if err != nil {
		t.Fatal(err)
	}
	if node.Type != NodeBinaryOp || node.Op != "&&" {
		t.Fatalf("expected && op, got %s", node)
	}
	if node.Children[0].Type != NodeCall {
		t.Errorf("expected left=call, got %d", node.Children[0].Type)
	}
	if node.Children[1].Type != NodeBinaryOp || node.Children[1].Op != "==" {
		t.Errorf("expected right== comparison, got %s", node.Children[1])
	}
}

func TestParseOr(t *testing.T) {
	node, err := Parse(`contains(body, "a") || contains(header, "b")`)
	if err != nil {
		t.Fatal(err)
	}
	if node.Op != "||" {
		t.Fatalf("expected || op, got %s", node.Op)
	}
}

func TestParseNot(t *testing.T) {
	node, err := Parse(`!contains(body, "error")`)
	if err != nil {
		t.Fatal(err)
	}
	if node.Type != NodeUnaryOp || node.Op != "!" {
		t.Fatalf("expected unary !, got %s", node)
	}
}

func TestParseContainsAll(t *testing.T) {
	node, err := Parse(`contains_all(body, "a", "b", "c")`)
	if err != nil {
		t.Fatal(err)
	}
	if node.FuncName != "contains_all" {
		t.Fatalf("expected contains_all, got %s", node.FuncName)
	}
	if len(node.Children) != 4 {
		t.Fatalf("expected 4 args, got %d", len(node.Children))
	}
}

func TestParseParenthesized(t *testing.T) {
	node, err := Parse(`(contains(body, "a") || contains(body, "b")) && status_code == 200`)
	if err != nil {
		t.Fatal(err)
	}
	if node.Op != "&&" {
		t.Fatalf("expected &&, got %s", node.Op)
	}
	if node.Children[0].Op != "||" {
		t.Errorf("expected left=||, got %s", node.Children[0].Op)
	}
}

func TestParseNestedCalls(t *testing.T) {
	node, err := Parse(`contains(body, "x") && contains(header, "y") && status_code == 200`)
	if err != nil {
		t.Fatal(err)
	}
	// should be ((a && b) && c) due to left-associativity
	if node.Op != "&&" {
		t.Fatalf("expected &&, got %s", node)
	}
	if node.Children[0].Op != "&&" {
		t.Errorf("expected left to be &&, got %s", node.Children[0])
	}
}

func TestParseString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`contains(body, "test")`, `contains(body, "test")`},
		{`a == 200`, `(a == "200")`},
		{`!x`, `(!x)`},
	}
	for _, tt := range tests {
		node, err := Parse(tt.input)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tt.input, err)
			continue
		}
		got := node.String()
		if got != tt.expected {
			t.Errorf("Parse(%q).String() = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
