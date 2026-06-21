package convert

import (
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/dsl"
)

// ParseToAST parses an xray expression string into a neutron dsl.Node AST.
// Variable names use nuclei conventions: body, status_code, all_headers, server, etc.
func ParseToAST(expr string) (*dsl.Node, error) {
	tokens, err := xrayLex(expr)
	if err != nil {
		return nil, fmt.Errorf("lex: %v", err)
	}
	return parseTokensToAST(tokens)
}

func ParseToASTWithAliases(expr string, aliases map[string]string) (*dsl.Node, error) {
	tokens, err := xrayLex(expr)
	if err != nil {
		return nil, fmt.Errorf("lex: %v", err)
	}
	rewriteIdentifierTokens(tokens, aliases)
	return parseTokensToAST(tokens)
}

func parseTokensToAST(tokens []xToken) (*dsl.Node, error) {
	p := &parser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().Type != xTEOF {
		return nil, fmt.Errorf("unexpected trailing token: %q at pos %d", p.peek().Val, p.pos)
	}
	return node, nil
}

func rewriteIdentifierTokens(tokens []xToken, aliases map[string]string) {
	if len(aliases) == 0 {
		return
	}
	for i := range tokens {
		if tokens[i].Type != xTIdent {
			continue
		}
		alias, ok := aliases[tokens[i].Val]
		if !ok {
			continue
		}
		if i > 0 && tokens[i-1].Type == xTDot {
			continue
		}
		if i+1 < len(tokens) && (tokens[i+1].Type == xTDot || tokens[i+1].Type == xTLParen) {
			continue
		}
		tokens[i].Val = alias
	}
}

type parser struct {
	tokens []xToken
	pos    int
}

func (p *parser) peek() xToken {
	if p.pos >= len(p.tokens) {
		return xToken{xTEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() xToken {
	t := p.peek()
	if t.Type != xTEOF {
		p.pos++
	}
	return t
}

func (p *parser) lookAhead(offset int) xToken {
	idx := p.pos + offset
	if idx >= len(p.tokens) {
		return xToken{xTEOF, ""}
	}
	return p.tokens[idx]
}

func (p *parser) expect(typ xTokenType) (xToken, error) {
	t := p.next()
	if t.Type != typ {
		return t, fmt.Errorf("expected token type %d, got %d (%q) at pos %d", typ, t.Type, t.Val, p.pos)
	}
	return t, nil
}

func (p *parser) parseOr() (*dsl.Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == xTOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = dsl.BinaryOp("||", left, right)
	}
	return left, nil
}

func (p *parser) parseAnd() (*dsl.Node, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == xTAnd {
		p.next()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = dsl.BinaryOp("&&", left, right)
	}
	return left, nil
}

func (p *parser) parseComparison() (*dsl.Node, error) {
	left, err := p.parseAdditive()
	if err != nil {
		return nil, err
	}

	switch p.peek().Type {
	case xTEq, xTNeq, xTGt, xTGte, xTLt, xTLte:
		op := p.next()
		right, err := p.parseAdditive()
		if err != nil {
			return nil, err
		}
		return buildComparisonNode(left, op.Val, right), nil

	case xTIn:
		p.next()
		if p.peek().Type == xTIdent && p.peek().Val == "response" {
			// "X" in response.headers → header existence check
			// Use contains(all_headers, "normalized_name:") instead of
			// variable != "" because some header vars (content_length) are
			// always set to computed values even when the header is absent.
			p.next() // response
			if p.peek().Type == xTDot {
				p.next()
			}
			if p.peek().Type == xTIdent {
				p.next() // headers
			}
			if left.Type == dsl.NodeLiteral {
				hdrName, _ := left.Value.(string)
				varName := headerVarName(hdrName)
				return dsl.Call("contains", dsl.Variable("all_headers"), dsl.Literal(varName+":")), nil
			}
			return dsl.BinaryOp("!=", left, dsl.Literal("")), nil
		}
		if p.peek().Type == xTLBracket {
			p.next() // [
			var items []*dsl.Node
			for p.peek().Type != xTRBracket && p.peek().Type != xTEOF {
				if p.peek().Type == xTComma {
					p.next()
					continue
				}
				item, err := p.parseAdditive()
				if err != nil {
					return nil, err
				}
				items = append(items, item)
			}
			if p.peek().Type == xTRBracket {
				p.next()
			}
			if len(items) == 0 {
				return dsl.Literal(false), nil
			}
			result := buildComparisonNode(left, "==", items[0])
			for _, item := range items[1:] {
				result = dsl.BinaryOp("||", result, buildComparisonNode(left, "==", item))
			}
			return result, nil
		}
	}
	return left, nil
}

func (p *parser) parseAdditive() (*dsl.Node, error) {
	left, err := p.parseMultiplicative()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == xTPlus || p.peek().Type == xTMinus {
		op := p.next()
		right, err := p.parseMultiplicative()
		if err != nil {
			return nil, err
		}
		left = buildArithmeticNode(op.Val, left, right)
	}
	return left, nil
}

func (p *parser) parseMultiplicative() (*dsl.Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == xTStar || p.peek().Type == xTSlash || p.peek().Type == xTPercent {
		op := p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = buildArithmeticNode(op.Val, left, right)
	}
	return left, nil
}

func (p *parser) parseUnary() (*dsl.Node, error) {
	if p.peek().Type == xTNot {
		p.next()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return dsl.UnaryOp("!", operand), nil
	}
	if p.peek().Type == xTMinus {
		p.next()
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return buildArithmeticNode("-", dsl.Literal(0), operand), nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (*dsl.Node, error) {
	tok := p.peek()

	switch tok.Type {
	case xTLParen:
		p.next()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(xTRParen); err != nil {
			return nil, err
		}
		return node, nil

	case xTString:
		p.next()
		// "pattern".matches(target) or .submatch(target)
		if p.peek().Type == xTDot && p.lookAhead(1).Type == xTIdent {
			method := p.lookAhead(1).Val
			if isReverseRegexMethod(method) && p.lookAhead(2).Type == xTLParen {
				p.next() // .
				p.next() // method
				p.next() // (
				arg, err := p.parseOr()
				if err != nil {
					return nil, err
				}
				if _, err := p.expect(xTRParen); err != nil {
					return nil, err
				}
				if method == "submatch" || method == "bsubmatch" {
					if group := p.consumeSubscriptValue(); group != nil {
						return p.maybeMethodCall(dsl.Call("xray_regex_group", dsl.Literal(tok.Val), arg, group))
					}
				}
				p.skipSubscript()
				return p.maybeMethodCall(dsl.Call("regex", dsl.Literal(tok.Val), arg))
			}
		}
		// "X" in response.headers → handled in parseComparison
		return p.maybeMethodCall(dsl.Literal(tok.Val))

	case xTNumber:
		p.next()
		if strings.Contains(tok.Val, ".") {
			var f float64
			fmt.Sscanf(tok.Val, "%f", &f)
			return dsl.Literal(f), nil
		}
		var n int
		fmt.Sscanf(tok.Val, "%d", &n)
		return dsl.Literal(n), nil

	case xTBool:
		p.next()
		return dsl.Literal(tok.Val == "true"), nil

	case xTIdent:
		if tok.Val == "response" {
			return p.parseResponseAccess()
		}
		if tok.Val == "request" {
			return p.parseRequestAccess()
		}
		return p.parseFuncOrIdent()

	default:
		return nil, fmt.Errorf("unexpected token %q (type=%d) at pos %d", tok.Val, tok.Type, p.pos)
	}
}

func (p *parser) parseResponseAccess() (*dsl.Node, error) {
	p.next() // response
	if p.peek().Type != xTDot {
		return dsl.Variable("response"), nil
	}
	p.next() // .
	if p.peek().Type != xTIdent {
		return dsl.Variable("response"), nil
	}

	field := p.next().Val

	switch field {
	case "body", "body_string":
		return p.maybeMethodCall(dsl.Variable("body"))

	case "status":
		return dsl.Variable("status_code"), nil

	case "latency":
		return dsl.Variable("latency"), nil

	case "content_type":
		return p.maybeMethodCall(dsl.Variable("content_type"))

	case "raw_header":
		return p.maybeRawHeaderCall()

	case "title", "title_string":
		return p.maybeMethodCall(dsl.Variable("title"))

	case "headers":
		if p.peek().Type == xTLBracket {
			p.next() // [
			tok := p.peek()
			if tok.Type == xTString {
				hdrName := p.next().Val
				if p.peek().Type == xTRBracket {
					p.next()
				}
				varName := headerVarName(hdrName)
				return p.maybeMethodCallForHeader(varName)
			}
			if tok.Type == xTIdent {
				p.next() // consume the variable name
				if p.peek().Type == xTRBracket {
					p.next()
				}
				// Dynamic header access: response.headers[varName]
				// Cannot bind a specific header at DSL level; use all_headers.
				// Force startsWith/endsWith → contains since all_headers is the full block.
				return p.maybeMethodCallForAllHeaders()
			}
			return dsl.Variable("all_headers"), nil
		}
		return dsl.Variable("all_headers"), nil

	case "cert":
		return p.parseCertAccess()

	case "url":
		return p.consumeUnevaluable()

	case "getIconContent":
		if p.peek().Type == xTLParen {
			p.next()
			if p.peek().Type == xTRParen {
				p.next()
			}
		}
		return dsl.Variable("favicon_content"), nil

	case "icon":
		if p.peek().Type == xTLParen {
			p.next()
			if p.peek().Type == xTRParen {
				p.next()
			}
		}
		return dsl.Variable("favicon_content"), nil

	default:
		return p.maybeMethodCall(dsl.Variable(field))
	}
}

func (p *parser) parseRequestAccess() (*dsl.Node, error) {
	p.next() // request
	if p.peek().Type != xTDot {
		return dsl.Variable("request"), nil
	}
	p.next() // .
	if p.peek().Type != xTIdent {
		return dsl.Variable("request"), nil
	}
	field := p.next().Val
	if field != "url" {
		return p.maybeMethodCall(dsl.Variable(field))
	}
	if p.peek().Type != xTDot {
		return p.maybeMethodCall(dsl.Variable("BaseURL"))
	}
	p.next() // .
	if p.peek().Type != xTIdent {
		return dsl.Variable("BaseURL"), nil
	}
	switch p.next().Val {
	case "scheme":
		return p.maybeMethodCall(dsl.Variable("Scheme"))
	case "host":
		return p.maybeMethodCall(dsl.Variable("Hostname"))
	case "domain":
		return p.maybeMethodCall(dsl.Variable("Host"))
	case "path":
		return p.maybeMethodCall(dsl.Variable("Path"))
	default:
		return p.consumeUnevaluable()
	}
}

func (p *parser) parseCertAccess() (*dsl.Node, error) {
	if p.peek().Type != xTDot {
		return dsl.Variable("cert"), nil
	}
	p.next() // .
	if p.peek().Type != xTIdent {
		return dsl.Variable("cert"), nil
	}
	field := headerVarName(p.next().Val)
	// common.XrayCertFields is the single source of truth for which cert
	// subfields are evaluable; its values are the full data-map keys (already
	// "cert_"-prefixed) populated by the HTTP/SSL runtime via tlsx.FillCertDSL.
	// not_before/not_after stay string-valued, so the timeConvert chain is
	// unaffected.
	if key, ok := common.XrayCertFields[field]; ok {
		node, err := p.maybeMethodCall(dsl.Variable(key))
		if err != nil {
			return nil, err
		}
		return caseFoldCertMatch(node), nil
	}
	return nil, fmt.Errorf("unsupported xray response.cert.%s field", field)
}

// caseFoldCertMatch makes substring matching on X.509 DN fields case-insensitive.
// Certificate field casing (PA-820 vs pa-820, DigiCert vs digicert) is not
// semantic and varies across CAs/devices, so xray's case-sensitive contains()
// on cert.* is a common false-negative source; fingerprint practice treats
// these as case-insensitive. raw_cert (byte matching) is unaffected: it is not a
// structured field and never reaches here.
func caseFoldCertMatch(node *dsl.Node) *dsl.Node {
	if node != nil && node.Type == dsl.NodeCall && node.FuncName == "contains" && len(node.Children) == 2 {
		if isToLowerCall(node.Children[0]) || isToLowerCall(node.Children[1]) {
			return node
		}
		return caseInsensitiveContains(node.Children[0], node.Children[1])
	}
	return node
}

func (p *parser) consumeUnevaluable() (*dsl.Node, error) {
	for p.peek().Type == xTDot {
		p.next()
		if p.peek().Type == xTIdent {
			method := p.peek().Val
			p.next()
			if isMethodName(method) && p.peek().Type == xTLParen {
				p.next()
				depth := 1
				for p.peek().Type != xTEOF && depth > 0 {
					if p.peek().Type == xTLParen {
						depth++
					}
					if p.peek().Type == xTRParen {
						depth--
					}
					p.next()
				}
			}
		}
	}
	return dsl.Literal(true), nil
}

var methodMap = map[string]string{
	"contains":     "contains",
	"bcontains":    "contains",
	"icontains":    "icontains",
	"ibcontains":   "icontains",
	"matches":      "regex",
	"bmatches":     "regex",
	"startsWith":   "starts_with",
	"bstartsWith":  "starts_with",
	"ibstartsWith": "starts_with",
	"endsWith":     "ends_with",
	"bendsWith":    "ends_with",
	"ibendsWith":   "ends_with",
	"submatch":     "regex",
	"bsubmatch":    "regex",
}

func isMethodName(name string) bool {
	_, ok := methodMap[name]
	return ok
}

func isReverseRegexMethod(name string) bool {
	return name == "matches" || name == "bmatches" || name == "submatch" || name == "bsubmatch"
}

func isVersionMethod(name string) bool {
	switch name {
	case "versionLess", "versionGreater", "versionEqual":
		return true
	default:
		return false
	}
}

// maybeMethodCallForAllHeaders parses a method call on all_headers,
// downgrading startsWith/endsWith to contains since all_headers is the
// full header block (startsWith on the whole block is meaningless).
func (p *parser) maybeMethodCallForAllHeaders() (*dsl.Node, error) {
	receiver := dsl.Variable("all_headers")
	if p.peek().Type != xTDot {
		return receiver, nil
	}
	if p.lookAhead(1).Type != xTIdent || !isMethodName(p.lookAhead(1).Val) {
		return receiver, nil
	}
	if p.lookAhead(2).Type != xTLParen {
		return receiver, nil
	}
	p.next() // .
	method := p.next().Val
	p.next() // (
	arg, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(xTRParen); err != nil {
		return nil, err
	}
	fn := methodMap[method]
	if fn == "starts_with" || fn == "ends_with" {
		fn = "contains"
	}
	return buildMethodCall(fn, receiver, arg), nil
}

// maybeRawHeaderCall handles response.raw_header method calls.
// xray's raw_header contains original-case headers ("X-Jenkins: v");
// neutron exposes the same raw header block as the DSL variable "header".
func (p *parser) maybeRawHeaderCall() (*dsl.Node, error) {
	receiver := dsl.Variable("header")
	if p.peek().Type != xTDot {
		return receiver, nil
	}
	if p.lookAhead(1).Type != xTIdent || (!isMethodName(p.lookAhead(1).Val) && !isVersionMethod(p.lookAhead(1).Val)) {
		return receiver, nil
	}
	if p.lookAhead(2).Type != xTLParen {
		return receiver, nil
	}

	p.next() // .
	method := p.next().Val
	p.next() // (

	arg, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(xTRParen); err != nil {
		return nil, err
	}

	if isVersionMethod(method) {
		return p.maybeMethodCall(versionMethodCall(method, receiver, arg))
	}

	fn := methodMap[method]

	if fn == "regex" {
		return dsl.Call("regex", arg, receiver), nil
	}
	return buildMethodCall(fn, receiver, arg), nil
}

func (p *parser) maybeMethodCall(receiver *dsl.Node) (*dsl.Node, error) {
	if p.peek().Type != xTDot {
		return receiver, nil
	}
	if p.lookAhead(1).Type != xTIdent || (!isMethodName(p.lookAhead(1).Val) && !isVersionMethod(p.lookAhead(1).Val)) {
		return receiver, nil
	}
	if p.lookAhead(2).Type != xTLParen {
		return receiver, nil
	}

	p.next() // .
	method := p.next().Val
	p.next() // (

	arg, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(xTRParen); err != nil {
		return nil, err
	}

	if method == "submatch" || method == "bsubmatch" {
		if group := p.consumeSubscriptValue(); group != nil {
			pattern, corpus := regexCallArgs(receiver, arg)
			return p.maybeMethodCall(dsl.Call("xray_regex_group", pattern, corpus, group))
		}
		p.skipSubscript()
	}

	if isVersionMethod(method) {
		return p.maybeMethodCall(versionMethodCall(method, receiver, arg))
	}

	fn := methodMap[method]
	if fn == "regex" {
		pattern, corpus := regexCallArgs(receiver, arg)
		return dsl.Call("regex", pattern, corpus), nil
	}
	return buildMethodCall(fn, receiver, arg), nil
}

func (p *parser) maybeMethodCallForHeader(varName string) (*dsl.Node, error) {
	receiver := dsl.Variable(varName)
	if p.peek().Type != xTDot {
		return receiver, nil
	}
	if p.lookAhead(1).Type != xTIdent || (!isMethodName(p.lookAhead(1).Val) && !isVersionMethod(p.lookAhead(1).Val)) {
		return receiver, nil
	}
	if p.lookAhead(2).Type != xTLParen {
		return receiver, nil
	}
	node, err := p.maybeMethodCall(receiver)
	if err != nil {
		return nil, err
	}
	return dsl.BinaryOp("&&",
		dsl.Call("contains", dsl.Variable("all_headers"), dsl.Literal(varName+":")),
		node,
	), nil
}

func regexCallArgs(receiver, arg *dsl.Node) (*dsl.Node, *dsl.Node) {
	if isRegexPatternReceiver(receiver) {
		return receiver, arg
	}
	return arg, receiver
}

func buildMethodCall(fn string, receiver, arg *dsl.Node) *dsl.Node {
	if fn == "icontains" {
		return caseInsensitiveContains(receiver, arg)
	}
	return dsl.Call(fn, receiver, arg)
}

func caseInsensitiveContains(left, right *dsl.Node) *dsl.Node {
	return dsl.Call("contains", lowerStringNode(left), lowerStringNode(right))
}

func lowerStringNode(node *dsl.Node) *dsl.Node {
	if node != nil && node.Type == dsl.NodeLiteral {
		if s, ok := node.Value.(string); ok {
			return dsl.Literal(strings.ToLower(s))
		}
	}
	if isToLowerCall(node) {
		return node
	}
	return dsl.Call("to_lower", node)
}

func isToLowerCall(node *dsl.Node) bool {
	return node != nil && node.Type == dsl.NodeCall && node.FuncName == "to_lower" && len(node.Children) == 1
}

func versionMethodCall(method string, receiver, arg *dsl.Node) *dsl.Node {
	switch method {
	case "versionLess":
		return dsl.Call("compare_versions", receiver, versionConstraint("<", arg))
	case "versionGreater":
		return dsl.Call("compare_versions", receiver, versionConstraint(">", arg))
	case "versionEqual":
		return dsl.Call("compare_versions", receiver, versionConstraint("=", arg))
	default:
		return dsl.Call(method, receiver, arg)
	}
}

func versionConstraint(prefix string, value *dsl.Node) *dsl.Node {
	if value != nil && value.Type == dsl.NodeLiteral {
		switch v := value.Value.(type) {
		case string:
			return dsl.Literal(prefix + v)
		default:
			return dsl.Literal(prefix + fmt.Sprintf("%v", v))
		}
	}
	return dsl.Call("concat", dsl.Literal(prefix), dsl.Call("to_string", value))
}

func isRegexPatternReceiver(node *dsl.Node) bool {
	if node == nil {
		return false
	}
	if node.Type == dsl.NodeLiteral {
		_, ok := node.Value.(string)
		return ok
	}
	if node.Type == dsl.NodeCall && node.FuncName == "to_string" && len(node.Children) == 1 {
		child := node.Children[0]
		if child.Type == dsl.NodeLiteral {
			_, ok := child.Value.(string)
			return ok
		}
	}
	return false
}

func (p *parser) skipSubscript() {
	if p.peek().Type == xTLBracket {
		p.next()
		for p.peek().Type != xTRBracket && p.peek().Type != xTEOF {
			p.next()
		}
		if p.peek().Type == xTRBracket {
			p.next()
		}
	}
}

func (p *parser) consumeSubscriptValue() *dsl.Node {
	if p.peek().Type != xTLBracket {
		return nil
	}
	p.next()
	var group *dsl.Node
	if p.peek().Type == xTString || p.peek().Type == xTIdent || p.peek().Type == xTNumber {
		tok := p.next()
		group = dsl.Literal(tok.Val)
	} else {
		for p.peek().Type != xTRBracket && p.peek().Type != xTEOF {
			p.next()
		}
	}
	if p.peek().Type == xTRBracket {
		p.next()
	}
	return group
}

func (p *parser) parseFuncOrIdent() (*dsl.Node, error) {
	tok := p.next()

	if tok.Val == "faviconHash" && p.peek().Type == xTLParen {
		p.next() // (
		arg := dsl.Variable("favicon_content")
		if p.peek().Type != xTRParen && p.peek().Type != xTEOF {
			parsed, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			arg = parsed
		}
		if _, err := p.expect(xTRParen); err != nil {
			return nil, err
		}
		return p.maybeMethodCall(dsl.Call("favicon_hash", arg))
	}

	if p.peek().Type == xTLParen {
		p.next() // (
		var args []*dsl.Node
		for p.peek().Type != xTRParen && p.peek().Type != xTEOF {
			if len(args) > 0 {
				if _, err := p.expect(xTComma); err != nil {
					return nil, err
				}
			}
			arg, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
		}
		if _, err := p.expect(xTRParen); err != nil {
			return nil, err
		}
		return p.maybeMethodCall(convertFunctionCall(tok.Val, args))
	}

	return p.maybeMethodCall(dsl.Variable(convertVariableName(tok.Val)))
}

func convertFunctionCall(name string, args []*dsl.Node) *dsl.Node {
	switch name {
	case "size":
		return dsl.Call("len", args...)
	case "dir":
		// xray's dir(x) trims everything after the last "/" but keeps that "/".
		// Expand to nuclei-compatible replace_regex so the produced template no
		// longer relies on an xray/neutron-private dir() helper.
		if len(args) == 1 {
			return dsl.Call("replace_regex", args[0], dsl.Literal("/[^/]*$"), dsl.Literal("/"))
		}
	case "timeConvert":
		return dsl.Call("time_convert", args...)
	case "replaceAll":
		return dsl.Call("replace", args...)
	case "string":
		if len(args) == 1 {
			if args[0].Type == dsl.NodeLiteral {
				return args[0]
			}
			if isKnownStringVariable(args[0]) {
				return args[0]
			}
			return dsl.Call("to_string", args[0])
		}
	case "int":
		return dsl.Call("to_number", args...)
	case "bytes":
		if len(args) == 1 {
			return args[0]
		}
	case "randomInt":
		return dsl.Call("rand_int", args...)
	case "randomLowercase":
		if len(args) == 1 {
			return dsl.Call("rand_base", args[0], dsl.Literal("abcdefghijklmnopqrstuvwxyz"))
		}
	case "base64Decode":
		return dsl.Call("base64_decode", args...)
	case "hexDecode":
		return dsl.Call("hex_decode", args...)
	case "hex":
		return dsl.Call("hex_encode", args...)
	case "decToHex", "dec_to_hex":
		return dsl.Call("dec_to_hex", args...)
	case "rev":
		return dsl.Call("reverse", args...)
	case "upper", "toUpper", "to_upper":
		return dsl.Call("to_upper", args...)
	case "lower", "toLower", "to_lower":
		return dsl.Call("to_lower", args...)
	case "urlencode", "urlEncode", "urlencodeall", "urlEncodeAll", "url_encode":
		return dsl.Call("url_encode", args...)
	case "sha":
		return shaCall(args)
	case "now":
		return dsl.Call("unix_time", args...)
	case "sleep":
		return dsl.Call("wait_for", args...)
	case "versionIn":
		return dsl.Call("compare_versions", args...)
	case "isValidPage":
		return validPageExpression()
	}
	return dsl.Call(name, args...)
}

func shaCall(args []*dsl.Node) *dsl.Node {
	if len(args) == 2 && args[1] != nil && args[1].Type == dsl.NodeLiteral {
		if alg, ok := args[1].Value.(string); ok {
			switch strings.ToLower(strings.TrimSpace(alg)) {
			case "sha1", "sha-1":
				return dsl.Call("sha1", args[0])
			case "sha256", "sha-256":
				return dsl.Call("sha256", args[0])
			case "sha512", "sha-512":
				return dsl.Call("sha512", args[0])
			}
		}
	}
	return dsl.Call("sha", args...)
}

func validPageExpression() *dsl.Node {
	return dsl.BinaryOp("&&",
		dsl.BinaryOp("&&",
			dsl.BinaryOp(">=", dsl.Variable("status_code"), dsl.Literal(200)),
			dsl.BinaryOp("<", dsl.Variable("status_code"), dsl.Literal(400)),
		),
		dsl.BinaryOp(">", dsl.Call("len", dsl.Call("trim_space", dsl.Variable("body"))), dsl.Literal(0)),
	)
}

func convertVariableName(name string) string {
	switch name {
	case "randomstr":
		return "randstr"
	case "randomnum":
		return "randnum"
	default:
		return name
	}
}

func buildArithmeticNode(op string, left, right *dsl.Node) *dsl.Node {
	switch op {
	case "+":
		if isStringLikeNode(left) || isStringLikeNode(right) {
			return dsl.Call("concat", left, right)
		}
		return dsl.Call("xray_add", left, right)
	case "-":
		return dsl.Call("xray_sub", left, right)
	case "*":
		return dsl.Call("xray_mul", left, right)
	case "/":
		return dsl.Call("xray_div", left, right)
	case "%":
		return dsl.Call("xray_mod", left, right)
	default:
		return dsl.BinaryOp(op, left, right)
	}
}

func isStringLikeNode(node *dsl.Node) bool {
	if node == nil {
		return false
	}
	if node.Type == dsl.NodeLiteral {
		_, ok := node.Value.(string)
		return ok
	}
	if node.Type != dsl.NodeCall {
		return false
	}
	switch node.FuncName {
	case "to_string", "concat", "base64", "base64_decode", "hex_encode", "hex_decode", "dec_to_hex", "url_encode", "md5", "substr", "rand_base", "reverse", "to_upper", "to_lower":
		return true
	default:
		return false
	}
}

func isKnownStringVariable(node *dsl.Node) bool {
	if node == nil || node.Type != dsl.NodeVariable {
		return false
	}
	name, _ := node.Value.(string)
	if name == "body" || name == "title" || name == "all_headers" ||
		name == "content_type" || name == common.RawCertKey || strings.HasPrefix(name, "cert_") {
		return true
	}
	return false
}

func buildComparisonNode(left *dsl.Node, op string, right *dsl.Node) *dsl.Node {
	if op == ">" || op == ">=" || op == "<" || op == "<=" {
		if isXrayNumericComparison(left) || isXrayNumericComparison(right) {
			switch op {
			case ">":
				return dsl.Call("xray_gt", left, right)
			case ">=":
				return dsl.Call("xray_gte", left, right)
			case "<":
				return dsl.Call("xray_lt", left, right)
			case "<=":
				return dsl.Call("xray_lte", left, right)
			}
		}
	}
	if op != "==" && op != "!=" {
		return dsl.BinaryOp(op, left, right)
	}
	if part, ok := faviconHashPart(left); ok {
		hash := comparisonHashLiteral(right)
		if hash != "" {
			node := dsl.Call("contains", dsl.Variable(part), dsl.Literal(hash))
			if op == "!=" {
				return dsl.UnaryOp("!", node)
			}
			return node
		}
	}
	return dsl.BinaryOp(op, left, right)
}

func isXrayNumericComparison(node *dsl.Node) bool {
	if node == nil {
		return false
	}
	if node.Type == dsl.NodeVariable {
		name, _ := node.Value.(string)
		return name == "latency" || name == "duration" || strings.Contains(strings.ToLower(name), "latency")
	}
	if node.Type == dsl.NodeCall {
		switch node.FuncName {
		case "xray_add", "xray_sub", "xray_mul", "xray_div", "xray_mod", "to_number":
			return true
		}
	}
	for _, child := range node.Children {
		if isXrayNumericComparison(child) {
			return true
		}
	}
	return false
}

func faviconHashPart(node *dsl.Node) (string, bool) {
	if node == nil || node.Type != dsl.NodeCall {
		return "", false
	}
	if node.FuncName == "favicon_hash" {
		if len(node.Children) == 0 {
			return "favicon_hash", true
		}
		source := node.Children[0]
		if source.Type == dsl.NodeVariable && source.Value.(string) == "body" {
			return "body_favicon_hash", true
		}
		return "favicon_hash", true
	}
	if node.FuncName == "mmh3" && len(node.Children) == 1 {
		child := node.Children[0]
		if child.Type == dsl.NodeCall && child.FuncName == "icon" {
			return "favicon_hash", true
		}
		if child.Type == dsl.NodeVariable {
			switch child.Value.(string) {
			case "favicon_content":
				return "favicon_hash", true
			}
		}
	}
	return "", false
}

func comparisonHashLiteral(node *dsl.Node) string {
	if node == nil || node.Type != dsl.NodeLiteral {
		return ""
	}
	return fmt.Sprintf("%v", node.Value)
}

// headerVarName converts an HTTP header name to nuclei's variable convention.
// "Content-Type" → "content_type", "Server" → "server", "Set-Cookie" → "set_cookie"
func headerVarName(name string) string {
	return strings.ToLower(strings.Replace(strings.TrimSpace(name), "-", "_", -1))
}
