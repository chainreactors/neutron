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
	ast = TransformBodyFaviconRuntimeFieldsToBody(ast)
	return astToMatchers(ast), nil
}

func ExprToMatchersForFaviconBody(expr string) (*ConvertResult, error) {
	ast, err := ParseToAST(expr)
	if err != nil {
		return nil, err
	}
	ast = TransformFaviconRuntimeFieldsToBody(ast)
	return astToMatchers(ast), nil
}

func astToMatchers(node *dsl.Node) *ConvertResult {
	if node == nil {
		return &ConvertResult{MatchersCondition: "or"}
	}
	// Lift a top-level OR out of an AND (distributive expansion) so each branch
	// becomes its own matcher under matchers-condition: or, instead of one DSL
	// matcher holding the OR. govaluate aborts the *whole* expression when one
	// branch's function errors (e.g. compare_versions on an empty version
	// extract from xray_regex_group); splitting lets nuclei evaluate each
	// branch as an independent matcher, so one side erroring can't kill the
	// other. A && (B || C) -> (A && B) || (A && C). Guarded in distributeOrOverAnd.
	node = distributeOrOverAnd(node)
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

// distributeOrOverAnd rewrites a top-level AND that has an OR subtree so the OR
// becomes the top-level operator: A && (B || C) -> (A && B) || (A && C). After
// this, astToMatchers emits one matcher per branch under matchers-condition:
// "or", evaluated by nuclei independently rather than as one govaluate
// expression (where a single branch's function error aborts the rest).
//
// Guarded against combinatorial blowup: only a single OR subtree under a
// top-level AND is expanded (multiple would cartesian-product), and the OR must
// flatten to between 2 and 8 branches. Anything else is returned unchanged and
// falls back to the single-DSL-matcher path (tolerated by compare_versions).
func distributeOrOverAnd(node *dsl.Node) *dsl.Node {
	if node == nil || node.Type != dsl.NodeBinaryOp || node.Op != "&&" {
		return node
	}
	_, andChildren := flattenBinaryOp(node)

	orIdx := -1
	for i, c := range andChildren {
		if c.Type == dsl.NodeBinaryOp && c.Op == "||" {
			if orIdx != -1 {
				return node // more than one OR subtree under the AND: would explode
			}
			orIdx = i
		}
	}
	if orIdx == -1 {
		return node // no OR nested under this AND: nothing to distribute
	}

	_, orBranches := flattenBinaryOp(andChildren[orIdx])
	if len(orBranches) < 2 || len(orBranches) > 8 {
		return node // cap the number of emitted matchers
	}

	var common []*dsl.Node
	for i, c := range andChildren {
		if i != orIdx {
			common = append(common, c)
		}
	}

	var result *dsl.Node
	for _, b := range orBranches {
		branch := b
		// reattach the shared AND conditions in front of this OR branch
		for i := len(common) - 1; i >= 0; i-- {
			branch = dsl.BinaryOp("&&", common[i], branch)
		}
		if result == nil {
			result = branch
		} else {
			result = dsl.BinaryOp("||", result, branch)
		}
	}
	return result
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
		if part, _, ci, ok := containsWordParts(node); ok {
			fn := "contains"
			if ci {
				fn = "icontains"
			}
			key := groupKey{fn: fn, part: part}

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
	// title contains/icontains → regex on body scoped to <title> tag
	if word, ok := titleContainsWord(node); ok {
		pattern := "(?i)<title>[^<]*" + regexQuote(word) + "[^<]*</title>"
		return &operators.Matcher{Type: "regex", Part: "body", Regex: []string{pattern}}
	}

	// contains/icontains(part, word) → word matcher
	if part, word, ci, ok := containsWordParts(node); ok {
		m := &operators.Matcher{Type: "word", Part: part, Words: []string{word}}
		if ci {
			m.CaseInsensitive = true
		}
		return m
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
		p, w, icase, ok := containsWordParts(child)
		if !ok {
			return nil
		}
		if part == "" {
			part = p
		} else if part != p {
			return nil
		}
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

func faviconContains(node *dsl.Node) (string, string, bool) {
	if node == nil || node.Type != dsl.NodeCall || node.FuncName != "contains" || len(node.Children) != 2 {
		return "", "", false
	}
	partNode := node.Children[0]
	if partNode.Type != dsl.NodeVariable {
		return "", "", false
	}
	part, ok := partNode.Value.(string)
	if !ok || (part != "favicon_hash" && part != "body_favicon_hash") {
		return "", "", false
	}
	hash := literalString(node.Children[1])
	if hash == "" {
		return "", "", false
	}
	return part, hash, true
}

// variableToPart maps an AST variable to a matcher part.
// Body/all_headers map directly. Cert fields and raw_cert are first-class
// response parts populated by the shared tlsx runtime. Individual header
// variables (server, content_type, etc.) deliberately do not map to "header":
// searching the full header block would false-positive when the word appears in
// a different header.
func variableToPart(node *dsl.Node) string {
	if node.Type != dsl.NodeVariable {
		return ""
	}
	name := node.Value.(string)
	switch name {
	case "body":
		return "body"
	case "all_headers":
		return "header"
	case "raw_cert":
		return "raw_cert"
	}
	if strings.HasPrefix(name, "cert_") {
		return name
	}
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

func containsWordParts(node *dsl.Node) (part string, word string, caseInsensitive bool, ok bool) {
	left, right, caseInsensitive, ok := containsCallParts(node)
	if !ok {
		return "", "", false, false
	}
	word = literalString(right)
	if word == "" {
		return "", "", false, false
	}
	part = variableToPartWithWord(left, word)
	if part == "" {
		return "", "", false, false
	}
	return part, word, caseInsensitive, true
}

func titleContainsWord(node *dsl.Node) (string, bool) {
	left, right, _, ok := containsCallParts(node)
	if !ok || !isTitleVar(left) {
		return "", false
	}
	word := literalString(right)
	return word, word != ""
}

func containsCallParts(node *dsl.Node) (left *dsl.Node, right *dsl.Node, caseInsensitive bool, ok bool) {
	if node == nil || node.Type != dsl.NodeCall || len(node.Children) != 2 {
		return nil, nil, false, false
	}
	switch node.FuncName {
	case "contains":
	case "icontains":
		caseInsensitive = true
	default:
		return nil, nil, false, false
	}
	left = node.Children[0]
	right = node.Children[1]
	if unwrapped, lowered := unwrapToLowerCall(left); lowered {
		left = unwrapped
		caseInsensitive = true
	}
	if unwrapped, lowered := unwrapToLowerCall(right); lowered {
		right = unwrapped
		caseInsensitive = true
	}
	return left, right, caseInsensitive, true
}

func unwrapToLowerCall(node *dsl.Node) (*dsl.Node, bool) {
	if node != nil && node.Type == dsl.NodeCall && node.FuncName == "to_lower" && len(node.Children) == 1 {
		return node.Children[0], true
	}
	return node, false
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
	if word, ok := titleContainsWord(node); ok {
		pattern := "(?i)<title>[^<]*" + regexQuote(word) + "[^<]*</title>"
		return dsl.Call("regex", dsl.Literal(pattern), dsl.Variable("body"))
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

// TransformBodyFaviconRuntimeFieldsToBody rewrites faviconHash(response.body)
// into explicit nuclei-style DSL over the current response body.
func TransformBodyFaviconRuntimeFieldsToBody(node *dsl.Node) *dsl.Node {
	return transformFaviconRuntimeFieldsToBody(node, false)
}

// TransformFaviconRuntimeFieldsToBody rewrites converter-internal favicon fields
// into explicit nuclei-style DSL over the current response body. It is used when
// the converter emits a dedicated /favicon.ico request for xray getIconContent()
// expressions.
func TransformFaviconRuntimeFieldsToBody(node *dsl.Node) *dsl.Node {
	return transformFaviconRuntimeFieldsToBody(node, true)
}

func transformFaviconRuntimeFieldsToBody(node *dsl.Node, includeFetchedIcon bool) *dsl.Node {
	if node == nil {
		return nil
	}
	if hash, part, negate, ok := faviconContainsHash(node); ok {
		if includeFetchedIcon || part == "body_favicon_hash" {
			expr := dsl.BinaryOp("==", faviconBodyHashNodeForPart(part), dsl.Literal(hash))
			if negate {
				return dsl.UnaryOp("!", expr)
			}
			return expr
		}
	}
	if hash, bodyPart, negate, ok := suffixedBodyFaviconContainsHash(node); ok {
		expr := dsl.BinaryOp("==", faviconBodyHashNodeForBody(bodyPart), dsl.Literal(hash))
		if negate {
			return dsl.UnaryOp("!", expr)
		}
		return expr
	}
	if node.Type == dsl.NodeVariable {
		if name, ok := node.Value.(string); ok && includeFetchedIcon && name == "favicon_content" {
			return dsl.Variable("body")
		}
	}
	clone := &dsl.Node{
		Type: node.Type, Value: node.Value, Op: node.Op, FuncName: node.FuncName,
	}
	if len(node.Children) > 0 {
		clone.Children = make([]*dsl.Node, len(node.Children))
		for i, child := range node.Children {
			clone.Children[i] = transformFaviconRuntimeFieldsToBody(child, includeFetchedIcon)
		}
	}
	return clone
}

func faviconContainsHash(node *dsl.Node) (string, string, bool, bool) {
	negate := false
	if node.Type == dsl.NodeUnaryOp && node.Op == "!" && len(node.Children) == 1 {
		negate = true
		node = node.Children[0]
	}
	if part, hash, ok := faviconContains(node); ok && (part == "favicon_hash" || part == "body_favicon_hash") {
		return hash, part, negate, true
	}
	return "", "", false, false
}

func suffixedBodyFaviconContainsHash(node *dsl.Node) (string, string, bool, bool) {
	negate := false
	if node.Type == dsl.NodeUnaryOp && node.Op == "!" && len(node.Children) == 1 {
		negate = true
		node = node.Children[0]
	}
	if node == nil || node.Type != dsl.NodeCall || node.FuncName != "contains" || len(node.Children) != 2 {
		return "", "", false, false
	}
	partNode := node.Children[0]
	if partNode.Type != dsl.NodeVariable {
		return "", "", false, false
	}
	part, ok := partNode.Value.(string)
	if !ok {
		return "", "", false, false
	}
	bodyPart, ok := bodyPartForFaviconHashPart(part)
	if !ok {
		return "", "", false, false
	}
	hash := literalString(node.Children[1])
	if hash == "" {
		return "", "", false, false
	}
	return hash, bodyPart, negate, true
}

func faviconBodyHashNode() *dsl.Node {
	return faviconBodyHashNodeForBody("body")
}

func faviconBodyHashNodeForPart(part string) *dsl.Node {
	if bodyPart, ok := bodyPartForFaviconHashPart(part); ok {
		return faviconBodyHashNodeForBody(bodyPart)
	}
	return faviconBodyHashNodeForBody("body")
}

func faviconBodyHashNodeForBody(bodyPart string) *dsl.Node {
	return dsl.Call("mmh3", dsl.Call("base64_py", dsl.Variable(bodyPart)))
}

func bodyPartForFaviconHashPart(part string) (string, bool) {
	if part == "body_favicon_hash" || part == "favicon_hash" {
		return "body", true
	}
	const prefix = "body_favicon_hash_"
	if strings.HasPrefix(part, prefix) && len(part) > len(prefix) {
		suffix := part[len(prefix):]
		for _, r := range suffix {
			if r < '0' || r > '9' {
				return "", false
			}
		}
		return "body_" + suffix, true
	}
	return "", false
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

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7e || s[i] < 0x20 {
			return true
		}
	}
	return false
}

func toHex(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&out, "%02x", s[i])
	}
	return out.String()
}
