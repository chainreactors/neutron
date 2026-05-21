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

// ParseTopExpression parses an xray POC top-level expression into the
// simplified rule-call tree used by the converter. It is exported for
// harness-style tooling that needs the same rule ordering semantics.
func ParseTopExpression(expr string) *TopExprNode {
	return parseTopExpression(expr)
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

// hasANY returns true if the expression tree contains any AND node.
func hasANY(node *TopExprNode) bool {
	if node == nil {
		return false
	}
	if node.Type == "and" {
		return true
	}
	for _, child := range node.Children {
		if hasANY(child) {
			return true
		}
	}
	return false
}

// topExprToString serializes a simplified TopExprNode back to a logic string.
func topExprToString(node *TopExprNode) string {
	if node == nil {
		return ""
	}
	switch node.Type {
	case "call":
		return node.Name
	case "and":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			s := topExprToString(child)
			if child.Type == "or" {
				s = "(" + s + ")"
			}
			parts[i] = s
		}
		return strings.Join(parts, " && ")
	case "or":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = topExprToString(child)
		}
		return strings.Join(parts, " || ")
	case "not":
		if len(node.Children) > 0 {
			return "!" + topExprToString(node.Children[0])
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

// substituteRuleExprs walks the top-level expression tree and replaces
// each rule call with the corresponding xray expression string.
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

// buildReqConditionDSL builds a single DSL expression for req-condition,
// suffixing variables by request index.
func buildReqConditionDSL(node *TopExprNode, rawExpr string, ruleExprs map[string]string, ruleReqIndex map[string][]int, lastIndex int, noSuffixVars map[string]bool) string {
	if needsRawTopExpression(rawExpr) && !hasMultiRequestIndex(ruleReqIndex) {
		if substituted, ok := substituteRuleCallsInExpression(rawExpr, ruleExprs, func(ruleName string) string {
			indices, ok := ruleReqIndex[ruleName]
			if !ok || len(indices) == 0 || indices[0] == lastIndex {
				return ""
			}
			return fmt.Sprintf("_%d", indices[0])
		}, noSuffixVars); ok {
			return substituted
		}
	}
	if node == nil {
		return "true"
	}
	switch node.Type {
	case "call":
		expr, ok := ruleExprs[node.Name]
		if !ok {
			return "true"
		}
		indices, ok := ruleReqIndex[node.Name]
		if !ok {
			return "(" + expr + ")"
		}
		parts := make([]string, 0, len(indices))
		for _, idx := range indices {
			if idx == lastIndex {
				parts = append(parts, "("+expr+")")
			} else {
				parts = append(parts, "("+suffixExprVars(expr, idx, noSuffixVars)+")")
			}
		}
		if len(parts) == 0 {
			return "(" + expr + ")"
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(" + strings.Join(parts, " || ") + ")"
	case "and":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = buildReqConditionDSL(child, "", ruleExprs, ruleReqIndex, lastIndex, noSuffixVars)
		}
		return "(" + strings.Join(parts, " && ") + ")"
	case "or":
		parts := make([]string, len(node.Children))
		for i, child := range node.Children {
			parts[i] = buildReqConditionDSL(child, "", ruleExprs, ruleReqIndex, lastIndex, noSuffixVars)
		}
		return "(" + strings.Join(parts, " || ") + ")"
	case "not":
		if len(node.Children) > 0 {
			return "!(" + buildReqConditionDSL(node.Children[0], "", ruleExprs, ruleReqIndex, lastIndex, noSuffixVars) + ")"
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

func hasMultiRequestIndex(ruleReqIndex map[string][]int) bool {
	for _, indices := range ruleReqIndex {
		if len(indices) > 1 {
			return true
		}
	}
	return false
}

func needsRawTopExpression(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}
	for _, marker := range []string{"==", "!=", ">=", "<=", ">", "<", ".", "[", "]", " in "} {
		if strings.Contains(expr, marker) {
			return true
		}
	}
	return false
}

func substituteRuleCallsInExpression(expr string, ruleExprs map[string]string, suffixFor func(string) string, noSuffixVars map[string]bool) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	ast, err := ParseToAST(expr)
	if err != nil {
		return "", false
	}
	replaced, changed, ok := replaceRuleCalls(ast, ruleExprs, suffixFor, noSuffixVars)
	if !ok || !changed {
		return "", false
	}
	return replaced.String(), true
}

func replaceRuleCalls(node *dsl.Node, ruleExprs map[string]string, suffixFor func(string) string, noSuffixVars map[string]bool) (*dsl.Node, bool, bool) {
	if node == nil {
		return nil, false, true
	}
	if node.Type == dsl.NodeCall && len(node.Children) == 0 {
		name := node.FuncName
		if expr, ok := ruleExprs[name]; ok {
			ruleAST, err := ParseToAST(expr)
			if err != nil {
				return nil, false, false
			}
			ruleAST = TransformTitleToBodyRegex(ruleAST)
			if suffixFor != nil {
				if suffix := suffixFor(name); suffix != "" {
					ruleAST = suffixRequestVariables(ruleAST, suffix, noSuffixVars)
				}
			}
			return ruleAST, true, true
		}
	}
	clone := &dsl.Node{
		Type: node.Type, Value: node.Value, Op: node.Op, FuncName: node.FuncName,
	}
	if len(node.Children) == 0 {
		return clone, false, true
	}
	clone.Children = make([]*dsl.Node, len(node.Children))
	changed := false
	for i, child := range node.Children {
		replaced, childChanged, ok := replaceRuleCalls(child, ruleExprs, suffixFor, noSuffixVars)
		if !ok {
			return nil, false, false
		}
		clone.Children[i] = replaced
		changed = changed || childChanged
	}
	return clone, changed, true
}

func suffixExprVars(expr string, reqIndex int, noSuffixVars map[string]bool) string {
	ast, err := ParseToAST(expr)
	if err != nil {
		return expr
	}
	suffix := fmt.Sprintf("_%d", reqIndex)
	suffixed := suffixRequestVariables(ast, suffix, noSuffixVars)
	return suffixed.String()
}

func suffixRequestVariables(node *dsl.Node, suffix string, noSuffixVars map[string]bool) *dsl.Node {
	if node == nil {
		return nil
	}
	clone := &dsl.Node{
		Type: node.Type, Value: node.Value, Op: node.Op, FuncName: node.FuncName,
	}
	if clone.Type == dsl.NodeVariable {
		name := clone.Value.(string)
		if !noSuffixVars[name] {
			clone.Value = name + suffix
		}
	}
	if len(node.Children) > 0 {
		clone.Children = make([]*dsl.Node, len(node.Children))
		for i, child := range node.Children {
			clone.Children[i] = suffixRequestVariables(child, suffix, noSuffixVars)
		}
	}
	return clone
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

// CollectRuleNames returns rule calls from a top-level expression tree in
// left-to-right order.
func CollectRuleNames(node *TopExprNode) []string {
	return collectRuleNames(node)
}
