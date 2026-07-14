package operators

import (
	"encoding/hex"
	"fmt"
	"github.com/Knetic/govaluate"
	"github.com/chainreactors/neutron/common"
	"regexp"
	"strings"
)

type Matcher struct {
	// Type is the type of the matcher
	Type string `json:"type" yaml:"type"`
	// Condition is the optional condition between two matcher variables
	//
	// By default, the condition is assumed to be OR.
	Condition string `json:"condition,omitempty" yaml:"condition,omitempty"`

	// Part is the part of the data to match
	Part string `json:"part,omitempty" yaml:"part,omitempty"`

	// Negative specifies if the match should be reversed
	// It will only match if the condition is not true.
	Negative bool `json:"negative,omitempty" yaml:"negative,omitempty"`

	// Name is matcher Name
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Status are the acceptable status codes for the response
	Status []int `json:"status,omitempty" yaml:"status,omitempty"`
	// Size is the acceptable size for the response
	Size []int `json:"size,omitempty" yaml:"size,omitempty"`
	// Words are the words required to be present in the response
	Words []string `json:"words,omitempty" yaml:"words,omitempty"`
	// Regex are the regex pattern required to be present in the response
	Regex []string `json:"regex,omitempty" yaml:"regex,omitempty"`
	// Binary are the binary characters required to be present in the response
	Binary []string `json:"binary,omitempty" yaml:"binary,omitempty"`
	// DSL are the dsl queries
	DSL []string `json:"dsl,omitempty" yaml:"dsl,omitempty"`
	// Hash are the favicon hashes (md5 or mmh3) to match
	Hash []string `json:"hash,omitempty" yaml:"hash,omitempty"`
	// JSON contains jq-style expressions used for matching json response
	JSON []string `json:"json,omitempty" yaml:"json,omitempty"`
	// XPath contains xpath expressions used for matching html/xml response
	XPath []string `json:"xpath,omitempty" yaml:"xpath,omitempty"`
	// Encoding specifies the encoding for the word content if any.
	Encoding string `json:"encoding,omitempty" yaml:"encoding,omitempty"`
	// description: |
	//   MatchAll enables matching for all matcher values. Default is false.
	// values:
	//   - false
	//   - true
	MatchAll        bool `yaml:"match-all,omitempty" json:"match-all,omitempty" `
	CaseInsensitive bool `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty" `
	condition       ConditionType
	matcherType     MatcherType
	regexCompiled   []*regexp.Regexp
	dslCompiled     []*govaluate.EvaluableExpression
	binaryDecoded   []string
	compiledData    interface{}
}

// Result reverts the results of the match if the matcher is of type negative.
func (m *Matcher) Result(data bool) bool {
	if m.Negative {
		return !data
	}
	return data
}

// ResultWithMatchedSnippet returns true and the matched snippet, or false and an empty string
func (m *Matcher) ResultWithMatchedSnippet(data bool, matchedSnippet []MatchHit) (bool, []MatchHit) {
	if m.Negative {
		return !data, nil
	}
	return data, matchedSnippet
}

// getType returns the type of the matcher
func (m *Matcher) GetType() MatcherType {
	return m.matcherType
}

// CompileMatchers performs the initial setup operation on a matcher
func (m *Matcher) CompileMatchers() error {
	var ok bool

	// Support hexadecimal encoding for matchers too.
	if m.Encoding == "hex" {
		for i, word := range m.Words {
			if decoded, err := hex.DecodeString(word); err == nil && len(decoded) > 0 {
				m.Words[i] = string(decoded)
			}
		}
	}

	// Setup the matcher type
	m.matcherType, ok = matcherTypes[m.Type]
	if !ok {
		return fmt.Errorf("unknown matcher type specified: %s", m.Type)
	}
	if m.Part == "" {
		if m.matcherType == FaviconMatcher {
			m.Part = "favicon_hash"
		} else {
			m.Part = "body"
		}
	}

	// Compile the regexes
	for _, regex := range m.Regex {
		regex = strings.TrimPrefix(regex, "(?x)")
		compiled, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("could not Compile regex: %s", regex)
		}
		m.regexCompiled = append(m.regexCompiled, compiled)
	}

	// Compile and validate binary Values in matcher
	for _, value := range m.Binary {
		if decoded, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("could not hex decode binary: %s", value)
		} else {
			m.binaryDecoded = append(m.binaryDecoded, string(decoded))
		}
	}

	// Compile the dsl expressions
	for _, dslExpression := range m.DSL {
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, common.GetHelperFunctions())
		if err != nil {
			return fmt.Errorf("could not compile dsl expression: %s", dslExpression)
		}
		m.dslCompiled = append(m.dslCompiled, compiledExpression)
	}

	// Setup the condition type, if any.
	if m.Condition != "" {
		m.condition, ok = conditionTypes[m.Condition]
		if !ok {
			return fmt.Errorf("unknown condition specified: %s", m.Condition)
		}
	} else {
		m.condition = ORCondition
	}
	if handler, ok := registeredMatchCompilers[m.matcherType]; ok {
		if err := handler(m); err != nil {
			return err
		}
	}

	if m.CaseInsensitive {
		if m.GetType() != WordsMatcher {
			return fmt.Errorf("case-insensitive flag is supported only for 'word' matchers (not '%s')", m.Type)
		}
		for i := range m.Words {
			m.Words[i] = strings.ToLower(m.Words[i])
		}
	}
	return nil
}

// MatchStatusCode matches a status code check against a corpus
func (m *Matcher) MatchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range m.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// MatchSize matches a size check against a corpus
func (m *Matcher) MatchSize(length int) bool {
	// Iterate over all the sizes accepted as valid
	//
	// Sizes codes don't support AND conditions.
	for _, size := range m.Size {
		// Continue if the size doesn't match
		if length != size {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// MatchWords matches a word check against a corpus.
func (matcher *Matcher) MatchWords(corpus string, data map[string]interface{}) (bool, []MatchHit) {
	if matcher.CaseInsensitive {
		corpus = strings.ToLower(corpus)
	}

	var matchedWords []MatchHit
	for i, word := range matcher.Words {
		if data == nil {
			data = make(map[string]interface{})
		}

		originalWord := word
		var err error
		if strings.Contains(word, common.ParenthesisOpen) || strings.Contains(word, common.General) {
			word, err = common.Evaluate(word, data)
			if err != nil {
				common.Logger().Warnf("Error while evaluating word matcher: %q", word)
				if matcher.condition == ANDCondition {
					return false, nil
				}
			}
		}
		if !strings.Contains(corpus, word) {
			switch matcher.condition {
			case ANDCondition:
				return false, nil
			case ORCondition:
				continue
			}
		}

		hit := MatchHit{Value: word, Rule: originalWord}
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, []MatchHit{hit}
		}
		matchedWords = append(matchedWords, hit)

		if len(matcher.Words)-1 == i && !matcher.MatchAll {
			return true, matchedWords
		}
	}
	if len(matchedWords) > 0 && matcher.MatchAll {
		return true, matchedWords
	}
	return false, nil
}

// MatchRegex matches a regex check against a corpus
func (matcher *Matcher) MatchRegex(corpus string) (bool, []MatchHit) {
	var matchedRegexes []MatchHit
	for i, regex := range matcher.regexCompiled {
		if !regex.MatchString(corpus) {
			switch matcher.condition {
			case ANDCondition:
				return false, nil
			case ORCondition:
				continue
			}
		}

		pattern := matcher.Regex[i]
		currentMatches := regex.FindAllString(corpus, -1)
		var hits []MatchHit
		for _, v := range currentMatches {
			hits = append(hits, MatchHit{Value: v, Rule: pattern})
		}
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, hits
		}

		matchedRegexes = append(matchedRegexes, hits...)

		if len(matcher.regexCompiled)-1 == i && !matcher.MatchAll {
			return true, matchedRegexes
		}
	}
	if len(matchedRegexes) > 0 && matcher.MatchAll {
		return true, matchedRegexes
	}
	return false, nil
}

// MatchBinary matches a binary check against a corpus
func (m *Matcher) MatchBinary(corpus string) (bool, []MatchHit) {
	var matchedBinary []MatchHit
	for i, binary := range m.binaryDecoded {
		if !strings.Contains(corpus, binary) {
			switch m.condition {
			case ANDCondition:
				return false, nil
			case ORCondition:
				continue
			}
		}

		rule := m.Binary[i]
		hit := MatchHit{Value: binary, Rule: rule}
		if m.condition == ORCondition {
			return true, []MatchHit{hit}
		}

		matchedBinary = append(matchedBinary, hit)

		if len(m.Binary)-1 == i {
			return true, matchedBinary
		}
	}
	return false, nil
}

// MatchDSL matches on a generic map result
func (m *Matcher) MatchDSL(data map[string]interface{}) bool {
	for i, expression := range m.dslCompiled {
		// Fast path: an expression with no template markers ({{...}} / §...§) is
		// returned unchanged by common.Evaluate, so re-resolving and recompiling it
		// on every response — across thousands of fingerprint templates — is pure
		// CPU waste. Reuse the already-compiled expression directly. Only expressions
		// that embed runtime markers take the slow resolve+recompile path.
		exprStr := expression.String()
		if strings.Contains(exprStr, common.ParenthesisOpen) || strings.Contains(exprStr, common.General) {
			resolvedExpression, err := common.Evaluate(exprStr, data)
			if err != nil {
				common.Logger().Errorf(m.Name, err)
				return false
			}
			expression, err = govaluate.NewEvaluableExpressionWithFunctions(resolvedExpression, common.GetHelperFunctions())
			if err != nil {
				common.Logger().Errorf(m.Name, err)
				return false
			}
		}

		result, err := expression.Evaluate(data)
		if err != nil {
			if m.condition == ANDCondition {
				return false
			}
			continue
		}

		if boolResult, ok := result.(bool); !ok {
			common.Logger().Warnf("[%s] The return value of a DSL statement must return a boolean value.", data["template-id"])
			continue
		} else if !boolResult {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch m.condition {
			case ANDCondition:
				return false
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the dsl, return with true
		if len(m.dslCompiled)-1 == i {
			return true
		}
	}
	return false
}

// MatchHashValues matches hash strings against matcher.Hash.
func (m *Matcher) MatchHashValues(values []string) (bool, []MatchHit) {
	if len(m.Hash) == 0 || len(values) == 0 {
		return false, nil
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}

	var matched []MatchHit
	for _, templateHash := range m.Hash {
		if _, ok := seen[templateHash]; ok {
			matched = append(matched, MatchHit{Value: templateHash, Rule: templateHash})
			if m.condition == ORCondition && !m.MatchAll {
				return true, matched
			}
			continue
		}
		if m.condition == ANDCondition {
			return false, nil
		}
	}
	if m.condition == ANDCondition || m.MatchAll {
		return len(matched) == len(m.Hash), matched
	}
	return len(matched) > 0, matched
}

func (m *Matcher) SetCompiledData(data interface{}) { m.compiledData = data }

func (m *Matcher) GetCompiledData() interface{} { return m.compiledData }

func (m *Matcher) GetCondition() ConditionType { return m.condition }

// MatchWithHandler dispatches matching to a registered handler.
func (m *Matcher) MatchWithHandler(corpus string, data map[string]interface{}) (bool, []MatchHit) {
	if handler, ok := registeredMatchHandlers[m.matcherType]; ok {
		return handler(m, corpus, data)
	}
	return false, nil
}
