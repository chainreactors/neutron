package convert

import (
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
)

// ParseToAST parses an xray expression string into a neutron dsl.Node AST.
// Variable names use nuclei conventions: body, status_code, all_headers, server, etc.
func ParseToAST(expr string) (*dsl.Node, error) {
	tokens, err := xrayLex(expr)
	if err != nil {
		return nil, fmt.Errorf("lex: %w", err)
	}
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
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	switch p.peek().Type {
	case xTEq, xTNeq, xTGt, xTGte, xTLt, xTLte:
		op := p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return dsl.BinaryOp(op.Val, left, right), nil

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
				item, err := p.parseUnary()
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
			result := dsl.BinaryOp("==", left, items[0])
			for _, item := range items[1:] {
				result = dsl.BinaryOp("||", result, dsl.BinaryOp("==", left, item))
			}
			return result, nil
		}
	}
	return left, nil
}

func (p *parser) parseUnary() (*dsl.Node, error) {
	if p.peek().Type == xTNot {
		p.next()
		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return dsl.UnaryOp("!", operand), nil
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
				p.skipSubscript()
				return dsl.Call("regex", dsl.Literal(tok.Val), arg), nil
			}
		}
		// "X" in response.headers → handled in parseComparison
		return dsl.Literal(tok.Val), nil

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

	case "content_type":
		return p.maybeMethodCall(dsl.Variable("content_type"))

	case "raw_header":
		return p.maybeRawHeaderCall()

	case "title", "title_string":
		return p.maybeMethodCall(dsl.Variable("title"))

	case "headers":
		if p.peek().Type == xTLBracket {
			p.next() // [
			if p.peek().Type != xTString {
				return dsl.Variable("all_headers"), nil
			}
			hdrName := p.next().Val
			if p.peek().Type == xTRBracket {
				p.next()
			}
			varName := headerVarName(hdrName)
			return p.maybeMethodCall(dsl.Variable(varName))
		}
		return dsl.Variable("all_headers"), nil

	case "cert", "url":
		return p.consumeUnevaluable()

	case "getIconContent":
		if p.peek().Type == xTLParen {
			p.next()
			if p.peek().Type == xTRParen {
				p.next()
			}
		}
		return dsl.Literal(""), nil

	default:
		return p.maybeMethodCall(dsl.Variable(field))
	}
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
	"contains":   "contains",
	"bcontains":  "contains",
	"icontains":  "icontains",
	"ibcontains": "icontains",
	"matches":    "regex",
	"bmatches":   "regex",
	"startsWith": "starts_with",
	"endsWith":   "ends_with",
	"submatch":   "regex",
	"bsubmatch":  "regex",
}

func isMethodName(name string) bool {
	_, ok := methodMap[name]
	return ok
}

func isReverseRegexMethod(name string) bool {
	return name == "matches" || name == "bmatches" || name == "submatch" || name == "bsubmatch"
}

// maybeRawHeaderCall handles response.raw_header method calls.
// xray's raw_header contains original-case headers ("X-Jenkins: v"),
// but neutron's all_headers uses normalized keys ("x_jenkins: v").
// We normalize the search argument to match neutron's format.
func (p *parser) maybeRawHeaderCall() (*dsl.Node, error) {
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

	// Normalize the search string: lowercase and replace hyphens with underscores
	// to match neutron's all_headers format.
	if arg.Type == dsl.NodeLiteral {
		if s, ok := arg.Value.(string); ok {
			normalized := strings.ToLower(strings.ReplaceAll(s, "-", "_"))
			arg = dsl.Literal(normalized)
		}
	}

	if fn == "regex" {
		return dsl.Call("regex", arg, receiver), nil
	}
	return dsl.Call(fn, receiver, arg), nil
}

func (p *parser) maybeMethodCall(receiver *dsl.Node) (*dsl.Node, error) {
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

	if method == "submatch" || method == "bsubmatch" {
		p.skipSubscript()
	}

	fn := methodMap[method]
	if fn == "regex" {
		return dsl.Call("regex", arg, receiver), nil
	}
	return dsl.Call(fn, receiver, arg), nil
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

func (p *parser) parseFuncOrIdent() (*dsl.Node, error) {
	tok := p.next()

	if tok.Val == "faviconHash" && p.peek().Type == xTLParen {
		p.next() // (
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
		return dsl.Call("favicon_hash", dsl.Literal("mock")), nil
	}

	if tok.Val == "size" {
		tok.Val = "len"
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
		return dsl.Call(tok.Val, args...), nil
	}

	return p.maybeMethodCall(dsl.Variable(tok.Val))
}

// headerVarName converts an HTTP header name to nuclei's variable convention.
// "Content-Type" → "content_type", "Server" → "server", "Set-Cookie" → "set_cookie"
func headerVarName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
}
