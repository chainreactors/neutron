package convert

import (
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
	"github.com/chainreactors/neutron/operators"
)

// ConvertResult holds the converted matchers and their condition.
type ConvertResult struct {
	Matchers          []*operators.Matcher
	MatchersCondition string // "and" or "or"
	Warnings          []string
}

// ExprToMatchers converts an xray expression to structured nuclei matchers.
func ExprToMatchers(expr string) (*ConvertResult, error) {
	ast, err := ParseToAST(expr)
	if err != nil {
		return nil, err
	}
	return astToMatchers(ast), nil
}

func astToMatchers(node *dsl.Node) *ConvertResult {
	if node == nil {
		return &ConvertResult{MatchersCondition: "or"}
	}
	r := &ConvertResult{MatchersCondition: "or"}

	topOp, children := flattenBinaryOp(node)
	if topOp == "&&" {
		r.MatchersCondition = "and"
	}

	merged := mergeCompatibleNodes(children, topOp)

	// First pass: collect all matchers
	var allMatchers []*operators.Matcher
	for _, child := range merged {
		if child.Type == dsl.NodeLiteral {
			if b, ok := child.Value.(bool); ok && b {
				continue
			}
		}

		m := nodeToMatcher(child)
		if m != nil {
			allMatchers = append(allMatchers, m)
		} else {
			dslStr := child.String()
			allMatchers = append(allMatchers, &operators.Matcher{
				Type: "dsl",
				DSL:  []string{dslStr},
			})
			r.Warnings = append(r.Warnings, "DSL fallback: "+dslStr)
		}
	}

	r.Matchers = allMatchers
	return r
}

func flattenBinaryOp(node *dsl.Node) (string, []*dsl.Node) {
	if node.Type != dsl.NodeBinaryOp || (node.Op != "&&" && node.Op != "||") {
		return "", []*dsl.Node{node}
	}
	op := node.Op
	var result []*dsl.Node
	var collect func(n *dsl.Node)
	collect = func(n *dsl.Node) {
		if n.Type == dsl.NodeBinaryOp && n.Op == op {
			collect(n.Children[0])
			collect(n.Children[1])
		} else {
			result = append(result, n)
		}
	}
	collect(node)
	return op, result
}

func mergeCompatibleNodes(nodes []*dsl.Node, topOp string) []*dsl.Node {
	if len(nodes) <= 1 {
		return nodes
	}

	type groupKey struct {
		fn   string
		part string
	}

	var result []*dsl.Node
	var currentGroup []*dsl.Node
	var currentKey *groupKey

	flush := func() {
		if len(currentGroup) <= 1 {
			result = append(result, currentGroup...)
		} else {
			combined := currentGroup[0]
			for _, n := range currentGroup[1:] {
				combined = dsl.BinaryOp(topOp, combined, n)
			}
			result = append(result, combined)
		}
		currentGroup = nil
		currentKey = nil
	}

	for _, node := range nodes {
		if node.Type == dsl.NodeCall &&
			(node.FuncName == "contains" || node.FuncName == "icontains") &&
			len(node.Children) == 2 {

			w := literalString(node.Children[1])
			part := variableToPartWithWord(node.Children[0], w)
			if part == "" {
				if currentKey != nil {
					flush()
				}
				result = append(result, node)
				continue
			}
			key := groupKey{fn: node.FuncName, part: part}

			if currentKey != nil && *currentKey == key {
				currentGroup = append(currentGroup, node)
			} else {
				if currentKey != nil {
					flush()
				}
				currentKey = &key
				currentGroup = []*dsl.Node{node}
			}
		} else {
			if currentKey != nil {
				flush()
			}
			result = append(result, node)
		}
	}
	if currentKey != nil {
		flush()
	}
	return result
}

func nodeToMatcher(node *dsl.Node) *operators.Matcher {
	if part, hash, ok := faviconContains(node); ok {
		return &operators.Matcher{Type: "favicon", Part: part, Hash: []string{hash}}
	}

	// title contains/icontains → regex on body scoped to <title> tag
	if node.Type == dsl.NodeCall && (node.FuncName == "contains" || node.FuncName == "icontains") && len(node.Children) == 2 {
		if isTitleVar(node.Children[0]) {
			word := literalString(node.Children[1])
			if word != "" {
				pattern := "(?i)<title>[^<]*" + regexQuote(word) + "[^<]*</title>"
				return &operators.Matcher{Type: "regex", Part: "body", Regex: []string{pattern}}
			}
		}
	}

	// contains/icontains(part, word) → word matcher
	if node.Type == dsl.NodeCall && (node.FuncName == "contains" || node.FuncName == "icontains") && len(node.Children) == 2 {
		word := literalString(node.Children[1])
		part := variableToPartWithWord(node.Children[0], word)
		if part != "" && word != "" {
			m := &operators.Matcher{Type: "word", Part: part, Words: []string{word}}
			if node.FuncName == "icontains" {
				m.CaseInsensitive = true
			}
			return m
		}
	}

	// regex(pattern, part) → regex matcher
	if node.Type == dsl.NodeCall && node.FuncName == "regex" && len(node.Children) == 2 {
		pattern := literalString(node.Children[0])
		part := variableToPart(node.Children[1])
		if pattern != "" && part != "" {
			return &operators.Matcher{Type: "regex", Part: part, Regex: []string{pattern}}
		}
	}

	// starts_with(part, prefix) → regex ^prefix
	if node.Type == dsl.NodeCall && node.FuncName == "starts_with" && len(node.Children) == 2 {
		part := variableToPart(node.Children[0])
		prefix := literalString(node.Children[1])
		if part != "" && prefix != "" {
			return &operators.Matcher{Type: "regex", Part: part, Regex: []string{"^" + regexQuote(prefix)}}
		}
	}

	// ends_with(part, suffix) → regex suffix$
	if node.Type == dsl.NodeCall && node.FuncName == "ends_with" && len(node.Children) == 2 {
		part := variableToPart(node.Children[0])
		suffix := literalString(node.Children[1])
		if part != "" && suffix != "" {
			return &operators.Matcher{Type: "regex", Part: part, Regex: []string{regexQuote(suffix) + "$"}}
		}
	}

	// status_code == N → status matcher
	if node.Type == dsl.NodeBinaryOp && node.Op == "==" && isStatusCode(node.Children[0]) {
		if code := literalInt(node.Children[1]); code != 0 {
			return &operators.Matcher{Type: "status", Status: []int{code}}
		}
	}

	// status_code != N → negative status matcher
	if node.Type == dsl.NodeBinaryOp && node.Op == "!=" && isStatusCode(node.Children[0]) {
		if code := literalInt(node.Children[1]); code != 0 {
			return &operators.Matcher{Type: "status", Status: []int{code}, Negative: true}
		}
	}

	// favicon_hash(...) == N → favicon matcher
	if node.Type == dsl.NodeBinaryOp && (node.Op == "==" || node.Op == "!=") {
		if node.Children[0].Type == dsl.NodeCall && node.Children[0].FuncName == "favicon_hash" {
			hash := literalAny(node.Children[1])
			if hash != "" {
				m := &operators.Matcher{Type: "favicon", Hash: []string{hash}}
				if node.Op == "!=" {
					m.Negative = true
				}
				return m
			}
		}
	}

	// title == "X" → regex on body scoped to <title> tag
	if node.Type == dsl.NodeBinaryOp && node.Op == "==" && isTitleVar(node.Children[0]) {
		val := literalString(node.Children[1])
		if val != "" {
			pattern := "(?i)<title>\\s*" + regexQuote(val) + "\\s*</title>"
			return &operators.Matcher{Type: "regex", Part: "body", Regex: []string{pattern}}
		}
	}

	// Variable == Literal (exact match, non-status, non-title) → word matcher
	if node.Type == dsl.NodeBinaryOp && node.Op == "==" && !isStatusCode(node.Children[0]) && !isTitleVar(node.Children[0]) {
		part := variableToPart(node.Children[0])
		val := literalString(node.Children[1])
		if part != "" && val != "" {
			return &operators.Matcher{Type: "word", Part: part, Words: []string{val}}
		}
	}

	// Variable != "" (existence check, only for actual empty string literals)
	if node.Type == dsl.NodeBinaryOp && node.Op == "!=" {
		if node.Children[0].Type == dsl.NodeVariable && isEmptyStringLiteral(node.Children[1]) {
			varName := node.Children[0].Value.(string)
			return &operators.Matcher{Type: "dsl", DSL: []string{varName + ` != ""`}}
		}
	}

	// true literal → skip
	if node.Type == dsl.NodeLiteral {
		if b, ok := node.Value.(bool); ok && b {
			return nil
		}
	}

	// !expr → negative matcher
	if node.Type == dsl.NodeUnaryOp && node.Op == "!" && len(node.Children) == 1 {
		inner := nodeToMatcher(node.Children[0])
		if inner != nil {
			inner.Negative = true
			return inner
		}
	}

	// Multiple same-type contains joined by AND/OR → merged word matcher
	if node.Type == dsl.NodeBinaryOp && (node.Op == "&&" || node.Op == "||") {
		if m := tryMergeWordMatchers(node); m != nil {
			return m
		}
		if m := tryMergeStatusMatchers(node); m != nil {
			return m
		}
		if m := tryMergeFaviconMatchers(node); m != nil {
			return m
		}
	}

	return nil
}

func tryMergeWordMatchers(node *dsl.Node) *operators.Matcher {
	op, children := flattenBinaryOp(node)
	if op != "&&" && op != "||" {
		return nil
	}
	var part string
	var words []string
	var ci *bool
	for _, child := range children {
		if child.Type != dsl.NodeCall || (child.FuncName != "contains" && child.FuncName != "icontains") || len(child.Children) != 2 {
			return nil
		}
		w := literalString(child.Children[1])
		p := variableToPartWithWord(child.Children[0], w)
		if p == "" || w == "" {
			return nil
		}
		if part == "" {
			part = p
		} else if part != p {
			return nil
		}
		icase := child.FuncName == "icontains"
		if ci == nil {
			ci = &icase
		} else if *ci != icase {
			return nil
		}
		words = append(words, w)
	}
	if len(words) < 2 {
		return nil
	}
	m := &operators.Matcher{Type: "word", Part: part, Words: words}
	if ci != nil && *ci {
		m.CaseInsensitive = true
	}
	if op == "&&" {
		m.Condition = "and"
	} else {
		m.Condition = "or"
	}
	return m
}

func tryMergeStatusMatchers(node *dsl.Node) *operators.Matcher {
	_, children := flattenBinaryOp(node)
	var codes []int
	for _, child := range children {
		if child.Type != dsl.NodeBinaryOp || child.Op != "==" || !isStatusCode(child.Children[0]) {
			return nil
		}
		code := literalInt(child.Children[1])
		if code == 0 {
			return nil
		}
		codes = append(codes, code)
	}
	if len(codes) < 2 {
		return nil
	}
	return &operators.Matcher{Type: "status", Status: codes}
}

func tryMergeFaviconMatchers(node *dsl.Node) *operators.Matcher {
	op, children := flattenBinaryOp(node)
	var hashes []string
	part := ""
	for _, child := range children {
		if child.Type == dsl.NodeBinaryOp && child.Op == "==" &&
			child.Children[0].Type == dsl.NodeCall && child.Children[0].FuncName == "favicon_hash" {
			hash := literalAny(child.Children[1])
			if hash != "" {
				hashes = append(hashes, hash)
				continue
			}
		}
		if p, hash, ok := faviconContains(child); ok {
			if part == "" {
				part = p
			} else if part != p {
				return nil
			}
			hashes = append(hashes, hash)
			continue
		}
		return nil
	}
	if len(hashes) < 2 {
		return nil
	}
	m := &operators.Matcher{Type: "favicon", Part: part, Hash: hashes}
	if op == "&&" {
		m.Condition = "and"
	}
	return m
}

func faviconContains(node *dsl.Node) (string, string, bool) {
	if node == nil || node.Type != dsl.NodeCall || node.FuncName != "contains" || len(node.Children) != 2 {
		return "", "", false
	}
	partNode := node.Children[0]
	if partNode.Type != dsl.NodeVariable {
		return "", "", false
	}
	part := partNode.Value.(string)
	if part != "favicon_hash" && part != "body_favicon_hash" {
		return "", "", false
	}
	hash := literalString(node.Children[1])
	if hash == "" {
		return "", "", false
	}
	return part, hash, true
}

// variableToPart maps an AST variable to a nuclei matcher part.
// Body and all_headers map directly. Individual header variables (server,
// content_type, etc.) map to "header" only when used in a contains/icontains
// call whose word argument has sufficient specificity (>= 3 chars).
// This avoids both: (a) false positives from too-generic words like ":" or "_",
// and (b) DSL fallback using functions (icontains) that may not exist at runtime.
func variableToPart(node *dsl.Node) string {
	if node.Type != dsl.NodeVariable {
		return ""
	}
	switch node.Value.(string) {
	case "body":
		return "body"
	case "all_headers":
		return "header"
	}
	// Individual header variable — caller will check word specificity
	// before deciding whether to use "header" part or fall back to DSL.
	return ""
}

// variableToPartWithWord maps a variable to a matcher part.
// Individual header variables (server, content_type, etc.) are NOT mapped
// to "header" part because that searches the full header block — causing
// false positives when the word appears in a different header. They fall
// through to DSL matchers which correctly target the specific variable.
func variableToPartWithWord(varNode *dsl.Node, word string) string {
	return variableToPart(varNode)
}

func isStatusCode(node *dsl.Node) bool {
	return node.Type == dsl.NodeVariable && node.Value.(string) == "status_code"
}

func literalString(node *dsl.Node) string {
	if node.Type == dsl.NodeLiteral {
		if s, ok := node.Value.(string); ok {
			return s
		}
	}
	return ""
}

func literalInt(node *dsl.Node) int {
	if node.Type != dsl.NodeLiteral {
		return 0
	}
	switch v := node.Value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

func literalAny(node *dsl.Node) string {
	if node.Type == dsl.NodeLiteral {
		return fmt.Sprintf("%v", node.Value)
	}
	return ""
}

// isTooPermissive detects matchers that are too broad to stand alone in an OR.
// e.g. status==200 alone would match almost every website.
func isTooPermissive(m *operators.Matcher) bool {
	if m.Type == "status" {
		for _, code := range m.Status {
			if code == 200 || code == 301 || code == 302 || code == 304 || code == 403 || code == 404 {
				return true
			}
		}
	}
	return false
}

func isTitleVar(node *dsl.Node) bool {
	return node.Type == dsl.NodeVariable && node.Value.(string) == "title"
}

// TransformTitleToBodyRegex replaces title variable usage in the AST
// with regex calls on body, for use in DSL expressions where no title
// variable is available at runtime.
func TransformTitleToBodyRegex(node *dsl.Node) *dsl.Node {
	if node == nil {
		return nil
	}
	if node.Type == dsl.NodeCall &&
		(node.FuncName == "contains" || node.FuncName == "icontains") &&
		len(node.Children) == 2 && isTitleVar(node.Children[0]) {
		word := literalString(node.Children[1])
		if word != "" {
			pattern := "(?i)<title>[^<]*" + regexQuote(word) + "[^<]*</title>"
			return dsl.Call("regex", dsl.Literal(pattern), dsl.Variable("body"))
		}
	}
	if node.Type == dsl.NodeBinaryOp && node.Op == "==" && isTitleVar(node.Children[0]) {
		val := literalString(node.Children[1])
		if val != "" {
			pattern := "(?i)<title>\\s*" + regexQuote(val) + "\\s*</title>"
			return dsl.Call("regex", dsl.Literal(pattern), dsl.Variable("body"))
		}
	}
	clone := &dsl.Node{
		Type: node.Type, Value: node.Value, Op: node.Op, FuncName: node.FuncName,
	}
	if len(node.Children) > 0 {
		clone.Children = make([]*dsl.Node, len(node.Children))
		for i, child := range node.Children {
			clone.Children[i] = TransformTitleToBodyRegex(child)
		}
	}
	return clone
}

func isEmptyStringLiteral(node *dsl.Node) bool {
	if node.Type != dsl.NodeLiteral {
		return false
	}
	s, ok := node.Value.(string)
	return ok && s == ""
}

func regexQuote(s string) string {
	special := `\.+*?()|[]{}^$`
	var out strings.Builder
	for _, c := range s {
		if strings.ContainsRune(special, c) {
			out.WriteByte('\\')
		}
		out.WriteRune(c)
	}
	return out.String()
}
