package dsl

import (
	"fmt"
	"unicode"
)

type TokenType int

const (
	TIdent  TokenType = iota // body, contains, status_code
	TString                  // "value" or 'value'
	TNumber                  // 200, 3.14
	TBool                    // true, false
	TLParen                  // (
	TRParen                  // )
	TComma                   // ,
	TAnd                     // &&
	TOr                      // ||
	TEq                      // ==
	TNeq                     // !=
	TGt                      // >
	TGte                     // >=
	TLt                      // <
	TLte                     // <=
	TNot                     // !
	TEOF
)

type Token struct {
	Type  TokenType
	Value string
	Pos   int
}

func (t Token) String() string { return fmt.Sprintf("{%d %q @%d}", t.Type, t.Value, t.Pos) }

func Lex(input string) ([]Token, error) {
	var tokens []Token
	runes := []rune(input)
	i := 0

	for i < len(runes) {
		if unicode.IsSpace(runes[i]) {
			i++
			continue
		}

		pos := i
		ch := runes[i]

		switch {
		case ch == '(' :
			tokens = append(tokens, Token{TLParen, "(", pos})
			i++
		case ch == ')':
			tokens = append(tokens, Token{TRParen, ")", pos})
			i++
		case ch == ',':
			tokens = append(tokens, Token{TComma, ",", pos})
			i++
		case ch == '&' && i+1 < len(runes) && runes[i+1] == '&':
			tokens = append(tokens, Token{TAnd, "&&", pos})
			i += 2
		case ch == '|' && i+1 < len(runes) && runes[i+1] == '|':
			tokens = append(tokens, Token{TOr, "||", pos})
			i += 2
		case ch == '=' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, Token{TEq, "==", pos})
			i += 2
		case ch == '!' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, Token{TNeq, "!=", pos})
			i += 2
		case ch == '>' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, Token{TGte, ">=", pos})
			i += 2
		case ch == '<' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, Token{TLte, "<=", pos})
			i += 2
		case ch == '>':
			tokens = append(tokens, Token{TGt, ">", pos})
			i++
		case ch == '<':
			tokens = append(tokens, Token{TLt, "<", pos})
			i++
		case ch == '!':
			tokens = append(tokens, Token{TNot, "!", pos})
			i++
		case ch == '"' || ch == '\'':
			s, end, err := lexString(runes, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, Token{TString, s, pos})
			i = end
		case unicode.IsDigit(ch):
			s, end := lexNumber(runes, i)
			tokens = append(tokens, Token{TNumber, s, pos})
			i = end
		case isIdentStart(ch):
			s, end := lexIdent(runes, i)
			if s == "true" || s == "false" {
				tokens = append(tokens, Token{TBool, s, pos})
			} else {
				tokens = append(tokens, Token{TIdent, s, pos})
			}
			i = end
		default:
			return nil, fmt.Errorf("unexpected character %q at position %d", ch, pos)
		}
	}

	tokens = append(tokens, Token{TEOF, "", i})
	return tokens, nil
}

func lexString(runes []rune, start int) (string, int, error) {
	quote := runes[start]
	i := start + 1
	var buf []byte
	for i < len(runes) {
		if runes[i] == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			switch next {
			case 'x':
				if i+3 < len(runes) {
					hi := hexDigitVal(runes[i+2])
					lo := hexDigitVal(runes[i+3])
					if hi >= 0 && lo >= 0 {
						buf = append(buf, byte(hi<<4|lo))
						i += 4
						continue
					}
				}
				buf = append(buf, byte(next))
				i += 2
			case 'n':
				buf = append(buf, '\n')
				i += 2
			case 'r':
				buf = append(buf, '\r')
				i += 2
			case 't':
				buf = append(buf, '\t')
				i += 2
			case '0':
				buf = append(buf, 0)
				i += 2
			default:
				buf = append(buf, byte(next))
				i += 2
			}
			continue
		}
		if runes[i] == quote {
			return string(buf), i + 1, nil
		}
		buf = append(buf, []byte(string(runes[i]))...)
		i++
	}
	return "", 0, fmt.Errorf("unterminated string at position %d", start)
}

func hexDigitVal(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10
	default:
		return -1
	}
}

func lexNumber(runes []rune, start int) (string, int) {
	i := start
	for i < len(runes) && (unicode.IsDigit(runes[i]) || runes[i] == '.') {
		i++
	}
	return string(runes[start:i]), i
}

func lexIdent(runes []rune, start int) (string, int) {
	i := start
	for i < len(runes) && isIdentChar(runes[i]) {
		i++
	}
	return string(runes[start:i]), i
}

func isIdentStart(ch rune) bool {
	return unicode.IsLetter(ch) || ch == '_'
}

func isIdentChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_'
}
