package operators

import (
	"fmt"

	"github.com/chainreactors/neutron/common/dsl"
)

func (m *Matcher) ToQuery() *dsl.Query {
	q := dsl.NewQuery()
	if m == nil {
		return q
	}
	part := dsl.NormalizePart(m.Part)

	var node *dsl.Node
	switch m.matcherType {
	case WordsMatcher:
		node = matcherWordsToNode(m, part, q)
	case StatusMatcher:
		node = matcherStatusToNode(m, q)
	case FaviconMatcher:
		node = matcherFaviconToNode(m, q)
	case DSLMatcher:
		node = matcherDSLToNode(m, q)
	case RegexMatcher:
		q.Errors = append(q.Errors, "regex matcher cannot be converted to search query")
	case BinaryMatcher:
		q.Errors = append(q.Errors, "binary matcher cannot be converted to search query")
	case SizeMatcher:
		q.Errors = append(q.Errors, "size matcher cannot be converted to search query")
	default:
		q.Errors = append(q.Errors, fmt.Sprintf("unknown matcher type: %d", m.matcherType))
	}

	if node != nil && m.Negative {
		node = dsl.UnaryOp("!", node)
	}
	q.Node = node
	return q
}

func (o *Operators) ToQuery() *dsl.Query {
	q := dsl.NewQuery()
	if o == nil {
		return q
	}
	var nodes []*dsl.Node

	for _, m := range o.Matchers {
		if m == nil {
			continue
		}
		mq := m.ToQuery()
		if mq == nil {
			continue
		}
		q.Warnings = append(q.Warnings, mq.Warnings...)
		q.Errors = append(q.Errors, mq.Errors...)
		if mq.Node != nil {
			nodes = append(nodes, mq.Node)
		}
	}

	q.Node = joinNodes(nodes, o.matchersCondition == ANDCondition)
	return q
}

func joinNodes(nodes []*dsl.Node, isAnd bool) *dsl.Node {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}
	op := "||"
	if isAnd {
		op = "&&"
	}
	result := nodes[0]
	for _, n := range nodes[1:] {
		result = dsl.BinaryOp(op, result, n)
	}
	return result
}

func matcherWordsToNode(m *Matcher, part string, q *dsl.Query) *dsl.Node {
	var nodes []*dsl.Node

	if part == "all" {
		for _, word := range m.Words {
			bodyCall := dsl.Call("contains", dsl.Variable("body"), dsl.Literal(word))
			headerCall := dsl.Call("contains", dsl.Variable("all_headers"), dsl.Literal(word))
			nodes = append(nodes, dsl.BinaryOp("||", bodyCall, headerCall))
		}
	} else {
		for _, word := range m.Words {
			nodes = append(nodes, dsl.Call("contains", dsl.Variable(part), dsl.Literal(word)))
		}
	}

	return joinNodes(nodes, m.condition == ANDCondition)
}

func matcherStatusToNode(m *Matcher, q *dsl.Query) *dsl.Node {
	var nodes []*dsl.Node
	for _, code := range m.Status {
		nodes = append(nodes, dsl.BinaryOp("==", dsl.Variable("status_code"), dsl.Literal(fmt.Sprintf("%d", code))))
	}
	return joinNodes(nodes, false)
}

func matcherFaviconToNode(m *Matcher, q *dsl.Query) *dsl.Node {
	var nodes []*dsl.Node
	for _, hash := range m.Hash {
		nodes = append(nodes, dsl.Call("favicon_hash", dsl.Literal(hash)))
	}
	return joinNodes(nodes, false)
}

func matcherDSLToNode(m *Matcher, q *dsl.Query) *dsl.Node {
	var nodes []*dsl.Node
	for _, expr := range m.DSL {
		node, err := dsl.Parse(expr)
		if err != nil {
			q.Errors = append(q.Errors, fmt.Sprintf("failed to parse DSL %q: %v", expr, err))
			continue
		}
		nodes = append(nodes, node)
	}
	return joinNodes(nodes, m.condition == ANDCondition)
}
