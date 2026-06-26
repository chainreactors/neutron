package dsl

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
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
	if node == nil {
		return r
	}
	if emitter == nil {
		r.Errors = append(r.Errors, "nil query emitter")
		return r
	}
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
		left := generateGrouped(node.Children[0], "&&", e, r)
		right := generateGrouped(node.Children[1], "&&", e, r)
		if left == "" {
			return right
		}
		if right == "" {
			return left
		}
		return e.And(left, right)
	case "||":
		left := generateGrouped(node.Children[0], "||", e, r)
		right := generateGrouped(node.Children[1], "||", e, r)
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

// generateGrouped wraps the child in parentheses when its operator has
// lower precedence than the parent — e.g. (A || B) inside an && node.
func generateGrouped(child *Node, parentOp string, e Emitter, r *Result) string {
	s := generate(child, e, r)
	if child.Type == NodeBinaryOp && parentOp == "&&" && child.Op == "||" {
		return e.Group(s)
	}
	return s
}

func genComparison(node *Node, e Emitter, r *Result) string {
	rawLeft := node.Children[0]
	left := unwrapFieldNode(rawLeft)
	right := node.Children[1]

	if IsFaviconBodyHashCall(rawLeft) {
		hash := resolveValue(right)
		q, err := e.FaviconHash(hash)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
			return ""
		}
		switch node.Op {
		case "==":
			return q
		case "!=":
			return e.Not(q)
		default:
			r.Warnings = append(r.Warnings, fmt.Sprintf("favicon hash operator %s approximated as equals", node.Op))
			return q
		}
	}

	if isStatusCodeVariable(left) {
		if code, ok := toInt(right); ok {
			clause := e.StatusCode(code)
			switch node.Op {
			case "==":
				return clause
			case "!=":
				return e.Not(clause)
			default:
				r.Warnings = append(r.Warnings, fmt.Sprintf("status_code operator %s approximated as equals", node.Op))
				return clause
			}
		}
	}

	if part, ok := variableName(left); ok {
		if isHeaderVariable(part, e) {
			needle := headerNeedle(part, resolveValue(right))
			clause := e.Contains(e.Field("all_headers"), needle)
			switch node.Op {
			case "==":
				return clause
			case "!=":
				return e.Not(clause)
			default:
				r.Warnings = append(r.Warnings, fmt.Sprintf("header variable operator %s approximated as contains", node.Op))
				return clause
			}
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

func IsFaviconBodyHashCall(node *Node) bool {
	if node == nil || node.Type != NodeCall || node.FuncName != "mmh3" || len(node.Children) != 1 {
		return false
	}
	child := node.Children[0]
	if child == nil || child.Type != NodeCall || child.FuncName != "base64_py" || len(child.Children) != 1 {
		return false
	}
	part, ok := variableName(child.Children[0])
	return ok && NormalizePart(part) == "body"
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

func genContains(node *Node, e Emitter, r *Result) string {
	if len(node.Children) < 2 {
		r.Errors = append(r.Errors, fmt.Sprintf("contains requires at least 2 args, got %d", len(node.Children)))
		return ""
	}
	fieldNode := unwrapFieldNode(node.Children[0])
	if fieldNode.Type == NodeVariable {
		part := NormalizePart(fieldNode.Value.(string))
		if part == "favicon_hash" || part == "body_favicon_hash" {
			q, err := e.FaviconHash(resolveValue(node.Children[1]))
			if err != nil {
				r.Errors = append(r.Errors, err.Error())
				return ""
			}
			return q
		}
		if isHeaderVariable(part, e) {
			needle := headerNeedle(part, resolveValue(node.Children[1]))
			return e.Contains(e.Field("all_headers"), needle)
		}
	}
	field := resolveField(fieldNode, e)
	value := resolveValue(node.Children[1])
	return e.Contains(field, value)
}

func genContainsMulti(node *Node, e Emitter, r *Result, isAll bool) string {
	if len(node.Children) < 2 {
		r.Errors = append(r.Errors, fmt.Sprintf("%s requires at least 2 args", node.FuncName))
		return ""
	}
	fieldNode := unwrapFieldNode(node.Children[0])
	field := resolveField(fieldNode, e)
	clauses := make([]string, 0, len(node.Children)-1)
	for _, arg := range node.Children[1:] {
		value := resolveValue(arg)
		if part, ok := variableName(fieldNode); ok {
			if isHeaderVariable(part, e) {
				clauses = append(clauses, e.Contains(e.Field("all_headers"), headerNeedle(part, value)))
				continue
			}
		}
		clauses = append(clauses, e.Contains(field, value))
	}
	if isAll {
		return e.Group(e.And(clauses...))
	}
	return e.Group(e.Or(clauses...))
}

func resolveField(node *Node, e Emitter) string {
	node = unwrapFieldNode(node)
	if node.Type == NodeVariable {
		if part, ok := node.Value.(string); ok {
			return e.Field(NormalizePart(part))
		}
	}
	return fmt.Sprintf("%v", node.Value)
}

func unwrapFieldNode(node *Node) *Node {
	for node != nil && node.Type == NodeCall && IsFieldTransparent(node.FuncName) && len(node.Children) == 1 {
		node = node.Children[0]
	}
	return node
}

// isHeaderVariable returns true if the emitter treats part as a generic header
// field (i.e. it has no dedicated platform mapping and falls through to the
// same target as "all_headers"). This replaces a hardcoded allowlist with the
// emitter's own knowledge of its field mappings.
func isHeaderVariable(part string, e Emitter) bool {
	if part == "" || part == "all_headers" || part == "header" || part == "body" || part == "status_code" {
		return false
	}
	return e.Field(part) == e.Field("all_headers")
}

func variableName(node *Node) (string, bool) {
	if node == nil || node.Type != NodeVariable {
		return "", false
	}
	part, ok := node.Value.(string)
	if !ok {
		return "", false
	}
	return NormalizePart(part), true
}

func isStatusCodeVariable(node *Node) bool {
	part, ok := variableName(node)
	return ok && part == "status_code"
}

func headerNeedle(part, value string) string {
	if value == "" {
		return part + ":"
	}
	return part + ": " + value
}

func resolveValue(node *Node) string {
	if node == nil {
		return ""
	}
	if node.Type == NodeCall && node.FuncName == "hex_decode" && len(node.Children) == 1 {
		if raw, ok := node.Children[0].Value.(string); ok {
			if decoded, err := hex.DecodeString(raw); err == nil {
				return escapeQueryBytes(decoded)
			}
		}
	}
	return fmt.Sprintf("%v", node.Value)
}

func escapeQueryBytes(value []byte) string {
	var builder strings.Builder
	for _, b := range value {
		if b < 0x20 || b == 0x7f || b >= 0x80 {
			fmt.Fprintf(&builder, `\x%02x`, b)
			continue
		}
		builder.WriteByte(b)
	}
	return builder.String()
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
	part = strings.TrimSpace(part)
	switch part {
	case "", "body", "body_string":
		return "body"
	case "header", "headers", "all_headers", "raw_header":
		return "all_headers"
	case "status", "status_code":
		return "status_code"
	default:
		if base, ok := stripRequestIndex(part); ok {
			switch base {
			case "", "body", "body_string":
				return "body"
			case "header", "headers", "all_headers", "raw_header":
				return "all_headers"
			case "status", "status_code":
				return "status_code"
			default:
				return base
			}
		}
	}
	return part
}

func stripRequestIndex(part string) (string, bool) {
	idx := strings.LastIndex(part, "_")
	if idx <= 0 || idx == len(part)-1 {
		return "", false
	}
	if _, err := strconv.Atoi(part[idx+1:]); err != nil {
		return "", false
	}
	return part[:idx], true
}
