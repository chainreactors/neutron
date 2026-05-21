package harness

import (
	"regexp"
	"strconv"
	"strings"
)

type groupHints map[string]string

func regexGroupKey(pattern, group string) string {
	return pattern + "\x00" + group
}

func regexSample(pattern string, hints groupHints) string {
	if pattern == "" {
		return "x"
	}
	return genAlternation(pattern, hints)
}

func regexGroupValue(pattern, sample, group string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	matches := re.FindStringSubmatch(sample)
	if len(matches) == 0 {
		return ""
	}
	if idx, err := strconv.Atoi(group); err == nil {
		if idx >= 0 && idx < len(matches) {
			return matches[idx]
		}
	}
	for i, name := range re.SubexpNames() {
		if name == group && i < len(matches) {
			return matches[i]
		}
	}
	if len(matches) > 1 {
		return matches[1]
	}
	return matches[0]
}

func genAlternation(pattern string, hints groupHints) string {
	parts := splitTopLevel(pattern, '|')
	if len(parts) > 0 {
		pattern = parts[0]
	}
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		var atom string
		switch ch {
		case '\\':
			atom, i = genEscape(pattern, i)
		case '[':
			atom, i = genClass(pattern, i)
		case '(':
			atom, i = genGroup(pattern, i, hints)
		case '.', '*', '+', '?':
			atom = literalForMeta(ch)
		case '^', '$':
			atom = ""
		default:
			atom = string(ch)
		}
		atom, i = applyQuantifier(pattern, i, atom)
		out.WriteString(atom)
	}
	return out.String()
}

func genEscape(pattern string, i int) (string, int) {
	if i+1 >= len(pattern) {
		return "\\", i
	}
	i++
	switch pattern[i] {
	case 'd':
		return "1", i
	case 'D':
		return "a", i
	case 'w':
		return "a", i
	case 'W':
		return "-", i
	case 's':
		return " ", i
	case 'S':
		return "a", i
	case 'b', 'B':
		return "", i
	case 'n':
		return "\n", i
	case 'r':
		return "\r", i
	case 't':
		return "\t", i
	default:
		return string(pattern[i]), i
	}
}

func genClass(pattern string, i int) (string, int) {
	j := i + 1
	if j < len(pattern) && pattern[j] == '^' {
		for j < len(pattern) && pattern[j] != ']' {
			j++
		}
		return "a", j
	}
	for j < len(pattern) && pattern[j] != ']' {
		if pattern[j] == '\\' && j+1 < len(pattern) {
			switch pattern[j+1] {
			case 'd':
				for j < len(pattern) && pattern[j] != ']' {
					j++
				}
				return "1", j
			case 'w':
				for j < len(pattern) && pattern[j] != ']' {
					j++
				}
				return "a", j
			}
			j += 2
			continue
		}
		if pattern[j] != '-' {
			ch := pattern[j]
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			return string(ch), j
		}
		j++
	}
	return "a", j
}

func genGroup(pattern string, i int, hints groupHints) (string, int) {
	close := findGroupClose(pattern, i)
	if close < 0 {
		return "(", i
	}
	innerStart := i + 1
	name := ""
	if strings.HasPrefix(pattern[innerStart:], "?P<") {
		end := strings.IndexByte(pattern[innerStart+3:], '>')
		if end >= 0 {
			name = pattern[innerStart+3 : innerStart+3+end]
			innerStart = innerStart + 3 + end + 1
		}
	} else if strings.HasPrefix(pattern[innerStart:], "?:") {
		innerStart += 2
	} else if strings.HasPrefix(pattern[innerStart:], "?i:") || strings.HasPrefix(pattern[innerStart:], "?s:") || strings.HasPrefix(pattern[innerStart:], "?m:") {
		innerStart += 3
	} else if strings.HasPrefix(pattern[innerStart:], "?i") || strings.HasPrefix(pattern[innerStart:], "?s") || strings.HasPrefix(pattern[innerStart:], "?m") {
		return "", close
	} else if strings.HasPrefix(pattern[innerStart:], "?=") || strings.HasPrefix(pattern[innerStart:], "?!") ||
		strings.HasPrefix(pattern[innerStart:], "?<=") || strings.HasPrefix(pattern[innerStart:], "?<!") {
		return "", close
	}
	if name != "" {
		if hint := hints[regexGroupKey(pattern, name)]; hint != "" {
			return hint, close
		}
	}
	return genAlternation(pattern[innerStart:close], hints), close
}

func findGroupClose(pattern string, open int) int {
	depth := 0
	for i := open; i < len(pattern); i++ {
		if pattern[i] == '\\' {
			i++
			continue
		}
		switch pattern[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func applyQuantifier(pattern string, i int, atom string) (string, int) {
	if i+1 >= len(pattern) {
		return atom, i
	}
	switch pattern[i+1] {
	case '*', '+', '?':
		i++
		if i+1 < len(pattern) && pattern[i+1] == '?' {
			i++
		}
		if atom == "" {
			return atom, i
		}
		return atom, i
	case '{':
		end := strings.IndexByte(pattern[i+2:], '}')
		if end < 0 {
			return atom, i
		}
		raw := pattern[i+2 : i+2+end]
		i = i + 2 + end
		n := 1
		first := raw
		if comma := strings.IndexByte(raw, ','); comma >= 0 {
			first = raw[:comma]
		}
		if parsed, err := strconv.Atoi(strings.TrimSpace(first)); err == nil && parsed > 0 {
			n = parsed
		}
		if i+1 < len(pattern) && pattern[i+1] == '?' {
			i++
		}
		return strings.Repeat(atom, n), i
	default:
		return atom, i
	}
}

func splitTopLevel(s string, sep byte) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if s[i] == sep && depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	if start == 0 {
		return nil
	}
	parts = append(parts, s[start:])
	return parts
}

func literalForMeta(ch byte) string {
	if ch == '.' {
		return "a"
	}
	return ""
}
