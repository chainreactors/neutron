package dsl

import (
	"fmt"
	"strings"
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
			return fmt.Sprintf("%q", s)
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

func Literal(v interface{}) *Node { return &Node{Type: NodeLiteral, Value: v} }
func Variable(name string) *Node { return &Node{Type: NodeVariable, Value: name} }
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
		Type:     n.Type,
		Value:    n.Value,
		Op:       n.Op,
		FuncName: n.FuncName,
	}
	if clone.Type == NodeVariable {
		clone.Value = clone.Value.(string) + suffix
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
