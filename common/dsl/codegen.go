package dsl

import (
	"fmt"
	"strconv"
)

type Emitter interface {
	Field(part string) string
	Contains(field, value string) string
	Equals(field, value string) string
	NotEquals(field, value string) string
	StatusCode(code int) string
	FaviconHash(hash string) (string, error)
	And(clauses ...string) string
	Or(clauses ...string) string
	Not(clause string) string
	Group(clause string) string
}

type Result struct {
	Query    string
	Warnings []string
	Errors   []string
}

func (r *Result) HasErrors() bool { return len(r.Errors) > 0 }

func Generate(node *Node, emitter Emitter) *Result {
	r := &Result{}
	r.Query = generate(node, emitter, r)
	return r
}

// Query is the platform-agnostic intermediate representation.
// Build it from matchers/templates, then call ToFOFA()/ToHunter()/ToCensys().
type Query struct {
	Node     *Node
	Metadata map[string][]string // platform -> pre-written queries
	Warnings []string
	Errors   []string
}

func NewQuery() *Query {
	return &Query{Metadata: make(map[string][]string)}
}

func (q *Query) ToFOFA() *Result   { return q.emit("fofa", &FOFAEmitter{}) }
func (q *Query) ToHunter() *Result { return q.emit("hunter", &HunterEmitter{}) }
func (q *Query) ToCensys() *Result { return q.emit("censys", &CensysEmitter{}) }

func (q *Query) Emit(platform string) *Result {
	e, ok := GetEmitter(platform)
	if !ok {
		return &Result{Errors: []string{fmt.Sprintf("unknown platform: %s", platform)}}
	}
	return q.emit(platform, e)
}

func (q *Query) emit(platform string, e Emitter) *Result {
	r := &Result{
		Warnings: q.Warnings,
		Errors:   q.Errors,
	}

	var clauses []string

	if metas, ok := q.Metadata[platform]; ok {
		clauses = append(clauses, metas...)
	}

	if q.Node != nil {
		gr := Generate(q.Node, e)
		r.Warnings = append(r.Warnings, gr.Warnings...)
		r.Errors = append(r.Errors, gr.Errors...)
		if gr.Query != "" {
			clauses = append(clauses, gr.Query)
		}
	}

	switch len(clauses) {
	case 0:
	case 1:
		r.Query = clauses[0]
	default:
		r.Query = e.Or(clauses...)
	}
	return r
}

func generate(node *Node, e Emitter, r *Result) string {
	switch node.Type {
	case NodeLiteral:
		return fmt.Sprintf("%v", node.Value)
	case NodeVariable:
		return node.Value.(string)
	case NodeBinaryOp:
		return genBinaryOp(node, e, r)
	case NodeUnaryOp:
		inner := generate(node.Children[0], e, r)
		return e.Not(inner)
	case NodeCall:
		return genCall(node, e, r)
	}
	return ""
}

func genBinaryOp(node *Node, e Emitter, r *Result) string {
	switch node.Op {
	case "&&":
		left := generate(node.Children[0], e, r)
		right := generate(node.Children[1], e, r)
		if left == "" {
			return right
		}
		if right == "" {
			return left
		}
		return e.And(left, right)
	case "||":
		left := generate(node.Children[0], e, r)
		right := generate(node.Children[1], e, r)
		if left == "" {
			return right
		}
		if right == "" {
			return left
		}
		return e.Or(left, right)
	case "==", "!=", ">", ">=", "<", "<=":
		return genComparison(node, e, r)
	}
	r.Errors = append(r.Errors, fmt.Sprintf("unsupported operator: %s", node.Op))
	return ""
}

func genComparison(node *Node, e Emitter, r *Result) string {
	left := node.Children[0]
	right := node.Children[1]

	if left.Type == NodeVariable && left.Value.(string) == "status_code" {
		if code, ok := toInt(right); ok {
			return e.StatusCode(code)
		}
	}

	field := resolveField(left, e)
	value := resolveValue(right)

	switch node.Op {
	case "==":
		return e.Equals(field, value)
	case "!=":
		return e.NotEquals(field, value)
	default:
		r.Warnings = append(r.Warnings, fmt.Sprintf("operator %s approximated as equals", node.Op))
		return e.Equals(field, value)
	}
}

func genCall(node *Node, e Emitter, r *Result) string {
	switch node.FuncName {
	case "contains":
		return genContains(node, e, r)
	case "contains_all":
		return genContainsMulti(node, e, r, true)
	case "contains_any":
		return genContainsMulti(node, e, r, false)
	case "starts_with":
		r.Warnings = append(r.Warnings, "starts_with approximated as contains")
		return genContains(node, e, r)
	case "ends_with":
		r.Warnings = append(r.Warnings, "ends_with approximated as contains")
		return genContains(node, e, r)
	case "favicon_hash":
		return genFaviconHash(node, e, r)
	default:
		r.Errors = append(r.Errors, fmt.Sprintf("unsupported function: %s", node.FuncName))
		return ""
	}
}

func genContains(node *Node, e Emitter, r *Result) string {
	if len(node.Children) < 2 {
		r.Errors = append(r.Errors, fmt.Sprintf("contains requires at least 2 args, got %d", len(node.Children)))
		return ""
	}
	field := resolveField(node.Children[0], e)
	value := resolveValue(node.Children[1])
	return e.Contains(field, value)
}

func genContainsMulti(node *Node, e Emitter, r *Result, isAll bool) string {
	if len(node.Children) < 2 {
		r.Errors = append(r.Errors, fmt.Sprintf("%s requires at least 2 args", node.FuncName))
		return ""
	}
	field := resolveField(node.Children[0], e)
	clauses := make([]string, 0, len(node.Children)-1)
	for _, arg := range node.Children[1:] {
		clauses = append(clauses, e.Contains(field, resolveValue(arg)))
	}
	if isAll {
		return e.Group(e.And(clauses...))
	}
	return e.Group(e.Or(clauses...))
}

func genFaviconHash(node *Node, e Emitter, r *Result) string {
	if len(node.Children) < 1 {
		r.Errors = append(r.Errors, "favicon_hash requires 1 arg")
		return ""
	}
	hash := resolveValue(node.Children[0])
	q, err := e.FaviconHash(hash)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return ""
	}
	return q
}

func resolveField(node *Node, e Emitter) string {
	if node.Type == NodeVariable {
		part := node.Value.(string)
		return e.Field(NormalizePart(part))
	}
	return fmt.Sprintf("%v", node.Value)
}

func resolveValue(node *Node) string {
	if node == nil {
		return ""
	}
	return fmt.Sprintf("%v", node.Value)
}

func toInt(node *Node) (int, bool) {
	switch v := node.Value.(type) {
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	case float64:
		return int(v), true
	case int:
		return v, true
	}
	return 0, false
}

func NormalizePart(part string) string {
	switch part {
	case "":
		return "body"
	case "header":
		return "all_headers"
	default:
		return part
	}
}
