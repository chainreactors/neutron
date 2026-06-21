package convert

import (
	"fmt"
	"strings"
	"unicode"
)

type xTokenType int

const (
	xTString   xTokenType = iota // all string literals
	xTNumber                     // 200, -123, 3.14
	xTBool                       // true, false
	xTIdent                      // identifiers
	xTDot                        // .
	xTLParen                     // (
	xTRParen                     // )
	xTLBracket                   // [
	xTRBracket                   // ]
	xTComma                      // ,
	xTAnd                        // &&
	xTOr                         // ||
	xTNot                        // !
	xTEq                         // ==
	xTNeq                        // !=
	xTGt                         // >
	xTGte                        // >=
	xTLt                         // <
	xTLte                        // <=
	xTIn                         // in
	xTPlus                       // +
	xTMinus                      // -
	xTStar                       // *
	xTSlash                      // /
	xTPercent                    // %
	xTQuestion                   // ?
	xTColon                      // :
	xTEOF
)

type xToken struct {
	Type xTokenType
	Val  string
}

func xrayLex(input string) ([]xToken, error) {
	s := strings.Replace(strings.Replace(input, "\r\n", " ", -1), "\n", " ", -1)
	runes := []rune(s)
	var tokens []xToken
	i := 0

	for i < len(runes) {
		if unicode.IsSpace(runes[i]) {
			i++
			continue
		}
		ch := runes[i]

		switch {
		case ch == '(':
			tokens = append(tokens, xToken{xTLParen, "("})
			i++
		case ch == ')':
			tokens = append(tokens, xToken{xTRParen, ")"})
			i++
		case ch == '[':
			tokens = append(tokens, xToken{xTLBracket, "["})
			i++
		case ch == ']':
			tokens = append(tokens, xToken{xTRBracket, "]"})
			i++
		case ch == ',':
			tokens = append(tokens, xToken{xTComma, ","})
			i++
		case ch == '.':
			tokens = append(tokens, xToken{xTDot, "."})
			i++
		case ch == '+':
			tokens = append(tokens, xToken{xTPlus, "+"})
			i++
		case ch == '-':
			if i+1 < len(runes) && unicode.IsDigit(runes[i+1]) && canBeNeg(tokens) {
				num, end := lexNumber(runes, i+1)
				tokens = append(tokens, xToken{xTNumber, "-" + num})
				i = end
			} else {
				tokens = append(tokens, xToken{xTMinus, "-"})
				i++
			}
		case ch == '*':
			tokens = append(tokens, xToken{xTStar, "*"})
			i++
		case ch == '/':
			tokens = append(tokens, xToken{xTSlash, "/"})
			i++
		case ch == '%':
			tokens = append(tokens, xToken{xTPercent, "%"})
			i++
		case ch == '?':
			tokens = append(tokens, xToken{xTQuestion, "?"})
			i++
		case ch == ':':
			tokens = append(tokens, xToken{xTColon, ":"})
			i++
		case ch == '&' && i+1 < len(runes) && runes[i+1] == '&':
			tokens = append(tokens, xToken{xTAnd, "&&"})
			i += 2
		case ch == '|' && i+1 < len(runes) && runes[i+1] == '|':
			tokens = append(tokens, xToken{xTOr, "||"})
			i += 2
		case ch == '=' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, xToken{xTEq, "=="})
			i += 2
		case ch == '!' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, xToken{xTNeq, "!="})
			i += 2
		case ch == '>' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, xToken{xTGte, ">="})
			i += 2
		case ch == '<' && i+1 < len(runes) && runes[i+1] == '=':
			tokens = append(tokens, xToken{xTLte, "<="})
			i += 2
		case ch == '>':
			tokens = append(tokens, xToken{xTGt, ">"})
			i++
		case ch == '<':
			tokens = append(tokens, xToken{xTLt, "<"})
			i++
		case ch == '!':
			tokens = append(tokens, xToken{xTNot, "!"})
			i++
		case ch == '"' || ch == '\'':
			val, end, err := lexString(runes, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, xToken{xTString, val})
			i = end
		case ch == 'b' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\''):
			val, end, err := lexString(runes, i+1)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, xToken{xTString, val})
			i = end
		case ch == 'r' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\''):
			val, end, err := lexRawString(runes, i+1)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, xToken{xTString, val})
			i = end
		case unicode.IsDigit(ch):
			num, end := lexNumber(runes, i)
			tokens = append(tokens, xToken{xTNumber, num})
			i = end
		case isIdentStart(ch):
			ident, end := lexIdent(runes, i)
			switch ident {
			case "true", "false":
				tokens = append(tokens, xToken{xTBool, ident})
			case "in":
				tokens = append(tokens, xToken{xTIn, "in"})
			case "bytes":
				if end < len(runes) && runes[end] == '(' {
					val, consumed, err := consumeBytesFunc(runes, end)
					if err == nil {
						tokens = append(tokens, xToken{xTString, val})
						i = consumed
						continue
					}
				}
				tokens = append(tokens, xToken{xTIdent, ident})
			default:
				tokens = append(tokens, xToken{xTIdent, ident})
			}
			i = end
		default:
			return nil, fmt.Errorf("unexpected character %q at position %d", ch, i)
		}
	}
	tokens = append(tokens, xToken{xTEOF, ""})
	return tokens, nil
}

func canBeNeg(tokens []xToken) bool {
	if len(tokens) == 0 {
		return true
	}
	last := tokens[len(tokens)-1].Type
	return last == xTEq || last == xTNeq || last == xTGt || last == xTGte ||
		last == xTLt || last == xTLte || last == xTIn ||
		last == xTLBracket || last == xTComma || last == xTLParen ||
		last == xTPlus || last == xTMinus || last == xTStar ||
		last == xTSlash || last == xTPercent
}

func lexString(runes []rune, start int) (string, int, error) {
	return lexStringMode(runes, start, false)
}

func lexRawString(runes []rune, start int) (string, int, error) {
	return lexStringMode(runes, start, true)
}

func lexStringMode(runes []rune, start int, raw bool) (string, int, error) {
	quote := runes[start]

	// Triple-quoted string: '''...''' or """..."""
	if start+2 < len(runes) && runes[start+1] == quote && runes[start+2] == quote {
		return lexTripleQuoteString(runes, start+3, raw, quote)
	}

	i := start + 1
	var buf []byte

	simpleClose := -1
	for j := i; j < len(runes); j++ {
		if runes[j] == '\\' && j+1 < len(runes) {
			j++
			continue
		}
		if runes[j] == quote {
			if isStringBoundary(runes, j+1) {
				simpleClose = j
				break
			}
			if simpleClose < 0 {
				simpleClose = j
			}
		}
	}
	if simpleClose < 0 {
		return "", 0, fmt.Errorf("unterminated string at position %d", start)
	}

	firstClose := -1
	for j := i; j < len(runes); j++ {
		if runes[j] == '\\' && j+1 < len(runes) {
			j++
			continue
		}
		if runes[j] == quote {
			firstClose = j
			break
		}
	}

	end := simpleClose
	if firstClose >= 0 && isStringBoundary(runes, firstClose+1) {
		end = firstClose
	}

	for j := i; j < end; j++ {
		if runes[j] == '\\' && j+1 < end {
			if raw {
				buf = append(buf, []byte(string(runes[j]))...)
				buf = append(buf, []byte(string(runes[j+1]))...)
			} else {
				next := runes[j+1]
				switch next {
				case 'x':
					if j+3 < end {
						hi := hexDigitVal(runes[j+2])
						lo := hexDigitVal(runes[j+3])
						if hi >= 0 && lo >= 0 {
							buf = append(buf, byte(hi<<4|lo))
							j += 3
							continue
						}
					}
					buf = append(buf, []byte(string(next))...)
				case 'n':
					buf = append(buf, '\n')
				case 'r':
					buf = append(buf, '\r')
				case 't':
					buf = append(buf, '\t')
				case '0':
					buf = append(buf, 0)
				default:
					buf = append(buf, []byte(string(next))...)
				}
			}
			j++
			continue
		}
		buf = append(buf, []byte(string(runes[j]))...)
	}
	return string(buf), end + 1, nil
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

func lexTripleQuoteString(runes []rune, start int, raw bool, quote rune) (string, int, error) {
	var buf []byte
	for j := start; j < len(runes); j++ {
		if runes[j] == quote && j+2 < len(runes) && runes[j+1] == quote && runes[j+2] == quote {
			return string(buf), j + 3, nil
		}
		if runes[j] == '\\' && j+1 < len(runes) && !raw {
			j++
			next := runes[j]
			switch next {
			case 'x':
				if j+2 < len(runes) {
					hi := hexDigitVal(runes[j+1])
					lo := hexDigitVal(runes[j+2])
					if hi >= 0 && lo >= 0 {
						buf = append(buf, byte(hi<<4|lo))
						j += 2
						continue
					}
				}
				buf = append(buf, []byte(string(next))...)
			case 'n':
				buf = append(buf, '\n')
			case 'r':
				buf = append(buf, '\r')
			case 't':
				buf = append(buf, '\t')
			case '0':
				buf = append(buf, 0)
			default:
				buf = append(buf, []byte(string(next))...)
			}
			continue
		}
		if runes[j] == '\\' && j+1 < len(runes) && raw {
			buf = append(buf, []byte(string(runes[j]))...)
			buf = append(buf, []byte(string(runes[j+1]))...)
			j++
			continue
		}
		buf = append(buf, []byte(string(runes[j]))...)
	}
	return "", 0, fmt.Errorf("unterminated triple-quoted string at position %d", start-3)
}

func isStringBoundary(runes []rune, pos int) bool {
	if pos >= len(runes) {
		return true
	}
	ch := runes[pos]
	if ch == ')' || ch == ',' || ch == ']' || ch == '.' ||
		ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '%' ||
		ch == '>' || ch == '<' || ch == '?' || ch == ':' {
		return true
	}
	j := pos
	for j < len(runes) && (runes[j] == ' ' || runes[j] == '\t') {
		j++
	}
	if j >= len(runes) {
		return true
	}
	ch = runes[j]
	if ch == ')' || ch == ',' || ch == ']' ||
		ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '%' ||
		ch == '>' || ch == '<' || ch == '?' || ch == ':' {
		return true
	}
	if ch == '&' && j+1 < len(runes) && runes[j+1] == '&' {
		return true
	}
	if ch == '|' && j+1 < len(runes) && runes[j+1] == '|' {
		return true
	}
	if ch == '=' && j+1 < len(runes) && runes[j+1] == '=' {
		return true
	}
	if ch == '!' && j+1 < len(runes) && runes[j+1] == '=' {
		return true
	}
	if j > pos && isIdentStart(ch) {
		end := j
		for end < len(runes) && isIdentChar(runes[end]) {
			end++
		}
		word := string(runes[j:end])
		if word == "in" || word == "and" || word == "or" {
			return true
		}
	}
	return false
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

func isIdentStart(ch rune) bool { return unicode.IsLetter(ch) || ch == '_' }
func isIdentChar(ch rune) bool  { return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_' }

func consumeBytesFunc(runes []rune, parenStart int) (string, int, error) {
	if parenStart >= len(runes) || runes[parenStart] != '(' {
		return "", 0, fmt.Errorf("expected (")
	}
	j := parenStart + 1
	for j < len(runes) && unicode.IsSpace(runes[j]) {
		j++
	}
	if j >= len(runes) || (runes[j] != '"' && runes[j] != '\'') {
		return "", 0, fmt.Errorf("expected string in bytes()")
	}
	val, end, err := lexString(runes, j)
	if err != nil {
		return "", 0, err
	}
	j = end
	for j < len(runes) && unicode.IsSpace(runes[j]) {
		j++
	}
	if j >= len(runes) || runes[j] != ')' {
		return "", 0, fmt.Errorf("expected ) in bytes()")
	}
	return val, j + 1, nil
}
