package dsl

import "fmt"

type parser struct {
	tokens []Token
	pos    int
}

func Parse(input string) (*Node, error) {
	tokens, err := Lex(input)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().Type != TEOF {
		return nil, fmt.Errorf("unexpected token %v", p.peek())
	}
	return node, nil
}

func (p *parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() Token {
	t := p.peek()
	if t.Type != TEOF {
		p.pos++
	}
	return t
}

func (p *parser) expect(typ TokenType) (Token, error) {
	t := p.next()
	if t.Type != typ {
		return t, fmt.Errorf("expected %d, got %v at position %d", typ, t.Value, t.Pos)
	}
	return t, nil
}

func (p *parser) parseOr() (*Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryOp("||", left, right)
	}
	return left, nil
}

func (p *parser) parseAnd() (*Node, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.peek().Type == TAnd {
		p.next()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = binaryOp("&&", left, right)
	}
	return left, nil
}

func (p *parser) parseComparison() (*Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	switch p.peek().Type {
	case TEq, TNeq, TGt, TGte, TLt, TLte:
		op := p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return binaryOp(op.Value, left, right), nil
	}
	return left, nil
}

func (p *parser) parseUnary() (*Node, error) {
	if p.peek().Type == TNot {
		p.next()
		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return unaryOp("!", operand), nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (*Node, error) {
	t := p.peek()

	switch t.Type {
	case TIdent:
		p.next()
		if p.peek().Type == TLParen {
			return p.parseCall(t.Value)
		}
		return variable(t.Value), nil

	case TString:
		p.next()
		return literal(t.Value), nil

	case TNumber:
		p.next()
		return literal(t.Value), nil

	case TBool:
		p.next()
		return literal(t.Value == "true"), nil

	case TLParen:
		p.next()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TRParen); err != nil {
			return nil, err
		}
		return node, nil
	}

	return nil, fmt.Errorf("unexpected token %q at position %d", t.Value, t.Pos)
}

func (p *parser) parseCall(name string) (*Node, error) {
	p.next() // consume '('
	var args []*Node
	for p.peek().Type != TRParen {
		if len(args) > 0 {
			if _, err := p.expect(TComma); err != nil {
				return nil, err
			}
		}
		arg, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}
	p.next() // consume ')'
	return call(name, args...), nil
}
