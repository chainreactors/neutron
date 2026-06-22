package dsl

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

type NodeType int

const (
	NodeLiteral  NodeType = iota // "string", 200, true
	NodeVariable                 // body, status_code, header
	NodeBinaryOp                 // left && right, left == right
	NodeUnaryOp                  // !expr
	NodeCall                     // contains(body, "test")
)

type Node struct {
	Type     NodeType
	Value    interface{}
	Op       string
	FuncName string
	Children []*Node
}

func (n *Node) String() string {
	switch n.Type {
	case NodeLiteral:
		if s, ok := n.Value.(string); ok {
			return quoteStringLiteral(s)
		}
		return fmt.Sprintf("%v", n.Value)
	case NodeVariable:
		return n.Value.(string)
	case NodeBinaryOp:
		return fmt.Sprintf("(%s %s %s)", n.Children[0], n.Op, n.Children[1])
	case NodeUnaryOp:
		return fmt.Sprintf("(%s%s)", n.Op, n.Children[0])
	case NodeCall:
		args := make([]string, len(n.Children))
		for i, c := range n.Children {
			args[i] = c.String()
		}
		return fmt.Sprintf("%s(%s)", n.FuncName, strings.Join(args, ", "))
	}
	return "?"
}

func quoteStringLiteral(s string) string {
	if needsHexDecodeLiteral(s) {
		return fmt.Sprintf("hex_decode(%q)", hex.EncodeToString([]byte(s)))
	}
	if isGovaluateDateLikeLiteral(s) {
		parts := make([]string, 0, len(s))
		for _, r := range s {
			parts = append(parts, quoteStringLiteralPlain(string(r)))
		}
		return "concat(" + strings.Join(parts, ", ") + ")"
	}
	return quoteStringLiteralPlain(s)
}

// needsHexDecodeLiteral reports whether a string literal must be emitted as
// hex_decode(...) instead of a plain quoted literal. Any control byte (incl.
// \t \n \r) or invalid UTF-8 must take this path.
//
// This looks stricter than nuclei's own DSL emission, but it is forced by the
// evaluation engine: govaluate (nuclei's DSL evaluator) only honours \" as an
// escape; for \n, \t, \r and every other \x it silently drops the backslash and
// keeps the following character. So a literal written as "a\nb" evaluates to the
// three runes a,n,b — it would match the letters "anb", never a real newline.
// hex_decode (a standard nuclei DSL function) is therefore the only way to make
// such bytes match correctly, and the emitted template stays nuclei-portable.
func needsHexDecodeLiteral(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func quoteStringLiteralPlain(s string) string {
	quoted := fmt.Sprintf("%q", s)
	return strings.Replace(quoted, `'`, `\'`, -1)
}

func isGovaluateDateLikeLiteral(s string) bool {
	if len(s) < len("2006-01-02") {
		return false
	}
	if s[4] != '-' || s[7] != '-' {
		return false
	}
	for _, idx := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
		if s[idx] < '0' || s[idx] > '9' {
			return false
		}
	}
	return true
}

func Literal(v interface{}) *Node { return &Node{Type: NodeLiteral, Value: v} }
func Variable(name string) *Node  { return &Node{Type: NodeVariable, Value: name} }
func BinaryOp(op string, l, r *Node) *Node {
	return &Node{Type: NodeBinaryOp, Op: op, Children: []*Node{l, r}}
}
func UnaryOp(op string, operand *Node) *Node {
	return &Node{Type: NodeUnaryOp, Op: op, Children: []*Node{operand}}
}
func Call(name string, args ...*Node) *Node {
	return &Node{Type: NodeCall, FuncName: name, Children: args}
}

// SuffixVariables deep-clones the AST and appends suffix to all Variable node names.
func SuffixVariables(n *Node, suffix string) *Node {
	if n == nil {
		return nil
	}
	clone := &Node{
		Type: n.Type, Value: n.Value, Op: n.Op, FuncName: n.FuncName,
	}
	if clone.Type == NodeVariable {
		if s, ok := clone.Value.(string); ok {
			clone.Value = s + suffix
		}
	}
	if len(n.Children) > 0 {
		clone.Children = make([]*Node, len(n.Children))
		for i, child := range n.Children {
			clone.Children[i] = SuffixVariables(child, suffix)
		}
	}
	return clone
}

// internal aliases for parser
var (
	literal  = Literal
	variable = Variable
	binaryOp = BinaryOp
	unaryOp  = UnaryOp
	call     = Call
)
