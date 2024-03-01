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
	// Encoding specifies the encoding for the word content if any.
	Encoding string `json:"encoding,omitempty" yaml:"encoding,omitempty"`

	MatchersCondition string `json:"matchers-condition" yaml:"matchers-condition"`
	Matchers          []Matcher
	condition         ConditionType
	matcherType       MatcherType
	regexCompiled     []*regexp.Regexp
	dslCompiled       []*govaluate.EvaluableExpression
	binaryDecoded     []string
}

// Result reverts the results of the match if the matcher is of type negative.
func (m *Matcher) Result(data bool) bool {
	if m.Negative {
		return !data
	}
	return data
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
	// By default, match on body if user hasn't provided any specific items
	if m.Part == "" {
		m.Part = "body"
	}

	// Compile the regexes
	for _, regex := range m.Regex {
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
		compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, common.HelperFunctions)
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
func (m *Matcher) MatchWords(corpus string) bool {
	// Iterate over all the words accepted as valid
	for i, word := range m.Words {
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the words, return with true
		if len(m.Words)-1 == i {
			return true
		}
	}
	return false
}

// MatchRegex matches a regex check against a corpus
func (m *Matcher) MatchRegex(corpus string) bool {
	// Iterate over all the regexes accepted as valid
	for i, regex := range m.regexCompiled {
		// Continue if the regex doesn't match
		if !regex.MatchString(corpus) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			if m.condition == ANDCondition {
				return false
			}
			// Continue with the flow since its an OR Condition.
			continue
		}

		// If the condition was an OR, return on the first match.
		if m.condition == ORCondition {
			return true
		}

		// If we are at the end of the regex, return with true
		if len(m.regexCompiled)-1 == i {
			return true
		}
	}
	return false
}

// MatchBinary matches a binary check against a corpus
func (matcher *Matcher) MatchBinary(corpus string) (bool, []string) {
	var matchedBinary []string
	// Iterate over all the words accepted as valid
	for i, binary := range matcher.binaryDecoded {
		if !strings.Contains(corpus, binary) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition {
			return true, []string{binary}
		}

		matchedBinary = append(matchedBinary, binary)

		// If we are at the end of the words, return with true
		if len(matcher.Binary)-1 == i {
			return true, matchedBinary
		}
	}
	return false, []string{}
}

// MatchDSL matches on a generic map result
func (matcher *Matcher) MatchDSL(data map[string]interface{}) bool {

	// Iterate over all the expressions accepted as valid
	for i, expression := range matcher.dslCompiled {
		resolvedExpression, err := common.Evaluate(expression.String(), data)
		if err != nil {
			common.NeutronLog.Errorf(matcher.Name, err)
			return false
		}
		expression, err = govaluate.NewEvaluableExpressionWithFunctions(resolvedExpression, common.HelperFunctions)
		if err != nil {
			common.NeutronLog.Errorf(matcher.Name, err)
			return false
		}

		result, err := expression.Evaluate(data)
		if err != nil {
			if matcher.condition == ANDCondition {
				return false
			}
			continue
		}

		if boolResult, ok := result.(bool); !ok {
			common.NeutronLog.Warnf("[%s] The return value of a DSL statement must return a boolean value.", data["template-id"])
			continue
		} else if !boolResult {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition {
			return true
		}

		// If we are at the end of the dsl, return with true
		if len(matcher.dslCompiled)-1 == i {
			return true
		}
	}
	return false
}
