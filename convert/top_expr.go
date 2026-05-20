package convert

import (
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
)

// TopExprNode represents a node in the parsed top-level expression tree.
type TopExprNode struct {
	Type     string // "and", "or", "call", "literal"
	Name     string // rule name for "call"
	Value    bool   // for "literal"
	Children []*TopExprNode
}

// parseTopExpression parses the POC's top-level expression into a simplified AST.
func parseTopExpression(expr string) *TopExprNode {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	tokens, err := xrayLex(expr)
	if err != nil {
		return nil
	}
	p := &topExprParser{tokens: tokens}
	result := p.parseOr()
	if result == nil {
		return nil
	}
	return simplifyTopExpr(result)
}

type topExprParser struct {
	tokens []xToken
	pos    int
}

func (p *topExprParser) peek() xToken {
	if p.pos >= len(p.tokens) {
		return xToken{xTEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *topExprParser) next() xToken {
	t := p.peek()
	if t.Type != xTEOF {
		p.pos++
	}
	return t
}

func (p *topExprParser) parseOr() *TopExprNode {
	left := p.parseAnd()
	if left == nil {
		return nil
	}
	children := []*TopExprNode{left}
	for p.peek().Type == xTOr {
		p.next()
		right := p.parseAnd()
		if right != nil {
			children = append(children, right)
		}
	}
	if len(children) == 1 {
		return children[0]
	}
	return &TopExprNode{Type: "or", Children: children}
}

func (p *topExprParser) parseAnd() *TopExprNode {
	left := p.parsePrimary()
	if left == nil {
		return nil
	}
	children := []*TopExprNode{left}
	for p.peek().Type == xTAnd {
		p.next()
		right := p.parsePrimary()
		if right != nil {
			children = append(children, right)
		}
	}
	if len(children) == 1 {
		return children[0]
	}
	return &TopExprNode{Type: "and", Children: children}
}

func (p *topExprParser) parsePrimary() *TopExprNode {
	tok := p.peek()
	switch tok.Type {
	case xTLParen:
		p.next()
		node := p.parseOr()
		if p.peek().Type == xTRParen {
			p.next()
		}
		return node
	case xTBool:
		p.next()
		return &TopExprNode{Type: "literal", Value: tok.Val == "true"}
	case xTIdent:
		name := tok.Val
		p.next()
		if p.peek().Type == xTLParen {
			p.next()
			if p.peek().Type == xTRParen {
				p.next()
			}
		}
		return &TopExprNode{Type: "call", Name: name}
	case xTNot:
		p.next()
		child := p.parsePrimary()
		if child != nil {
			return &TopExprNode{Type: "not", Children: []*TopExprNode{child}}
		}
		return nil
	default:
		return nil
	}
}

func simplifyTopExpr(node *TopExprNode) *TopExprNode {
	if node == nil {
		return nil
	}
	if len(node.Children) > 0 {
		var simplified []*TopExprNode
		for _, child := range node.Children {
			s := simplifyTopExpr(child)
			if s != nil {
				simplified = append(simplified, s)
			}
		}
		node.Children = simplified
	}

	switch node.Type {
	case "and":
		var filtered []*TopExprNode
		for _, child := range node.Children {
			if child.Type == "literal" && child.Value {
				continue
			}
			if child.Type == "literal" && !child.Value {
				return &TopExprNode{Type: "literal", Value: false}
			}
			filtered = append(filtered, child)
		}
		if len(filtered) == 0 {
			return &TopExprNode{Type: "literal", Value: true}
		}
		if len(filtered) == 1 {
			return filtered[0]
		}
		node.Children = filtered

	case "or":
		var filtered []*TopExprNode
		for _, child := range node.Children {
			if child.Type == "literal" && child.Value {
				return &TopExprNode{Type: "literal", Value: true}
			}
			if child.Type == "literal" && !child.Value {
				continue
			}
			filtered = append(filtered, child)
		}
		if len(filtered) == 0 {
			return &TopExprNode{Type: "literal", Value: false}
		}
		if len(filtered) == 1 {
			return filtered[0]
		}
		node.Children = filtered
	}
	return node
}

// hasANDAcrossGroups checks whether the top-level expression ANDs rules
// that belong to different request groups (i.e. require req-condition).
func hasANDAcrossGroups(node *TopExprNode, ruleGroup map[string]string) bool {
	if node == nil {
		return false
	}
	if node.Type == "and" {
		groups := map[string]bool{}
		for _, name := range collectRuleNames(node) {
			if g, ok := ruleGroup[name]; ok {
				groups[g] = true
			}
		}
		if len(groups) > 1 {
			return true
		}
	}
	for _, child := range node.Children {
		if hasANDAcrossGroups(child, ruleGroup) {
			return true
		}
	}
	return false
}

func collectRuleNames(node *TopExprNode) []string {
	if node == nil {
		return nil
	}
	if node.Type == "call" {
		return []string{node.Name}
	}
	var names []string
	for _, child := range node.Children {
		names = append(names, collectRuleNames(child)...)
	}
	return names
}

// substituteRuleExprs walks the top-level expression tree and replaces
// each rule call with the corresponding xray expression string,
// preserving the AND/OR structure.
func substituteRuleExprs(node *TopExprNode, ruleExprs map[string]string) string {
	if node == nil {
		return "true"
	}
	switch node.Type {
	case "call":
		if expr, ok := ruleExprs[node.Name]; ok {
			return "(" + strings.TrimSpace(expr) + ")"
		}
		return "true"
	case "and":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = substituteRuleExprs(child, ruleExprs)
		}
		return "(" + strings.Join(parts, " && ") + ")"
	case "or":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = substituteRuleExprs(child, ruleExprs)
		}
		return "(" + strings.Join(parts, " || ") + ")"
	case "not":
		if len(node.Children) > 0 {
			return "!(" + substituteRuleExprs(node.Children[0], ruleExprs) + ")"
		}
		return "true"
	case "literal":
		if node.Value {
			return "true"
		}
		return "false"
	}
	return "true"
}

// buildReqConditionDSL builds a single DSL expression for a req-condition
// template by suffixing variables with request indices.
func buildReqConditionDSL(node *TopExprNode, ruleExprs map[string]string, ruleReqIndex map[string]int, lastIndex int) string {
	if node == nil {
		return "true"
	}
	switch node.Type {
	case "call":
		expr, ok := ruleExprs[node.Name]
		if !ok {
			return "true"
		}
		idx, ok := ruleReqIndex[node.Name]
		if !ok {
			return "(" + expr + ")"
		}
		if idx == lastIndex {
			return "(" + expr + ")"
		}
		return "(" + suffixExprVars(expr, idx) + ")"
	case "and":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = buildReqConditionDSL(child, ruleExprs, ruleReqIndex, lastIndex)
		}
		return "(" + strings.Join(parts, " && ") + ")"
	case "or":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = buildReqConditionDSL(child, ruleExprs, ruleReqIndex, lastIndex)
		}
		return "(" + strings.Join(parts, " || ") + ")"
	case "not":
		if len(node.Children) > 0 {
			return "!(" + buildReqConditionDSL(node.Children[0], ruleExprs, ruleReqIndex, lastIndex) + ")"
		}
		return "true"
	case "literal":
		if node.Value {
			return "true"
		}
		return "false"
	}
	return "true"
}

// suffixExprVars parses an xray expression, converts it to a DSL AST,
// adds _N suffix to all variables, and returns the DSL string.
func suffixExprVars(expr string, reqIndex int) string {
	ast, err := ParseToAST(expr)
	if err != nil {
		return expr
	}
	suffix := fmt.Sprintf("_%d", reqIndex)
	suffixed := dsl.SuffixVariables(ast, suffix)
	return suffixed.String()
}
