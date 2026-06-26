package operators

import (
	"fmt"
	"github.com/chainreactors/neutron/common"
	"strconv"
)

// operators contains the operators that can be applied on protocols
type Operators struct {
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*Matcher `json:"matchers,omitempty" yaml:"matchers,omitempty"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*Extractor `json:"extractors,omitempty" yaml:"extractors,omitempty"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `json:"matchers-condition,omitempty" yaml:"matchers-condition,omitempty"`
	// cached variables that may be used along with request.
	matchersCondition ConditionType

	// TemplateID is the ID of the template for matcher
	TemplateID string `json:"templateID,omitempty" yaml:"templateID,omitempty"`
}

// Result is a result structure created from operators running on data.
type Result struct {
	// Matched is true if any matchers matched
	Matched bool
	// Extracted is true if any result type values were extracted
	Extracted bool
	// Matches is a map of matcher names that we matched
	Matches map[string][]string
	// Extracts contains all the data extracted from inputs
	Extracts map[string][]string
	// OutputExtracts is the list of extracts to be displayed on screen.
	OutputExtracts []string
	outputUnique   map[string]struct{}
	// DynamicValues contains any dynamic values to be templated
	DynamicValues map[string]interface{}
	// PayloadValues contains payload values provided by user. (Optional)
	PayloadValues map[string]interface{}
	// Request is the raw HTTP request for the match.
	Request string
	// Response is the raw HTTP response for the match.
	Response string
}

func (r *Operators) Compile() error {
	if r == nil {
		return fmt.Errorf("operators is nil")
	}
	if r.MatchersCondition != "" {
		r.matchersCondition = conditionTypes[r.MatchersCondition]
	} else {
		r.matchersCondition = ORCondition
	}
	for i, matcher := range r.Matchers {
		if matcher == nil {
			return fmt.Errorf("matcher at index %d is nil", i)
		}
		if err := matcher.CompileMatchers(); err != nil {
			return err
		}
	}
	for i, extractor := range r.Extractors {
		if extractor == nil {
			return fmt.Errorf("extractor at index %d is nil", i)
		}
		if err := extractor.CompileExtractors(); err != nil {
			return err
		}
	}
	return nil
}

// getMatchersCondition returns the condition for the matchers
func (r *Operators) GetMatchersCondition() ConditionType {
	return r.matchersCondition
}

type matchFunc func(data map[string]interface{}, matcher *Matcher) (bool, []string)
type extractFunc func(data map[string]interface{}, matcher *Extractor) map[string]struct{}

// Execute executes the operators on data and returns a result structure
func (operators *Operators) Execute(data map[string]interface{}, match matchFunc, extract extractFunc) (*Result, bool) {
	matcherCondition := operators.GetMatchersCondition()

	var matches bool
	result := &Result{
		Matches:       make(map[string][]string),
		Extracts:      make(map[string][]string),
		DynamicValues: make(map[string]interface{}),
		outputUnique:  make(map[string]struct{}),
	}

	// state variable to check if all extractors are internal
	var allInternalExtractors bool = true
	// Start with the extractors first and evaluate them.
	for _, extractor := range operators.Extractors {
		if !extractor.Internal && allInternalExtractors {
			allInternalExtractors = false
		}

		// DSL extractors: preserve original types from evaluation results
		if extractor.GetType() == DSLExtractor {
			typedResults := extractor.ExtractDSLTyped(data)
			if len(typedResults) == 0 {
				continue
			}
			if len(typedResults) == 1 {
				data[extractor.Name] = typedResults[0]
			} else {
				data[extractor.Name] = typedResults
			}
			if extractor.Internal {
				result.DynamicValues[extractor.Name] = data[extractor.Name]
			} else {
				for _, val := range typedResults {
					str := fmt.Sprint(val)
					if _, ok := result.outputUnique[str]; !ok {
						result.OutputExtracts = append(result.OutputExtracts, str)
						result.outputUnique[str] = struct{}{}
					}
				}
				if extractor.Name != "" {
					strs := make([]string, len(typedResults))
					for i, val := range typedResults {
						strs[i] = fmt.Sprint(val)
					}
					result.Extracts[extractor.Name] = strs
				}
			}
			continue
		}

		// Other extractors: string-based path
		var extractorResults []string
		for match := range extract(data, extractor) {
			extractorResults = append(extractorResults, match)

			if extractor.Internal {
				result.DynamicValues[extractor.Name] = match
			} else {
				if _, ok := result.outputUnique[match]; !ok {
					result.OutputExtracts = append(result.OutputExtracts, match)
					result.outputUnique[match] = struct{}{}
				}
			}
		}
		if len(extractorResults) > 0 && !extractor.Internal && extractor.Name != "" {
			result.Extracts[extractor.Name] = extractorResults
		}
		if len(extractorResults) > 0 {
			data[extractor.Name] = getExtractedValue(extractorResults)
		}
	}

	// expose dynamic values to same request matchers
	if len(result.DynamicValues) > 0 {
		data = common.MergeMaps(data, result.DynamicValues)
	}

	// 用于 AND 条件临时存储匹配结果
	var andMatches map[string][]string
	if matcherCondition == ANDCondition {
		andMatches = make(map[string][]string)
	}

	for matcherIndex, matcher := range operators.Matchers {
		if isMatch, matched := match(data, matcher); isMatch {
			common.Debug("Matched: %+v", matcher)
			if matcherCondition == ORCondition {
				// OR 条件：立即记录
				if matcher.Name != "" {
					result.Matches[matcher.Name] = matched
				}
			} else {
				// AND 条件：暂存到临时 map，等所有都通过后再记录
				matcherName := getMatcherName(matcher, matcherIndex)
				andMatches[matcherName] = matched
			}
			matches = true
		} else if matcherCondition == ANDCondition {
			common.Debug("Not Matched: %+v", matcher)
			return nil, false
		} else {
			common.Debug("Not Matched: %+v", matcher)
		}
	}

	// AND 条件且所有 matcher 都匹配成功，统一写入到 result.Matches
	if matcherCondition == ANDCondition && matches {
		result.Matches = andMatches
	}

	result.Matched = matches
	result.Extracted = len(result.OutputExtracts) > 0
	// Don't print if we have matchers and they have not matched, irregardless of extractor
	if len(operators.Matchers) > 0 && !matches {
		return nil, false
	}
	if len(result.DynamicValues) > 0 {
		return result, true
	}
	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(result.Extracts) > 0 || len(result.OutputExtracts) > 0 || matches {
		return result, true
	}

	return nil, true
}

// ExecuteInternalExtractors executes internal dynamic extractors
func (operators *Operators) ExecuteInternalExtractors(data map[string]interface{}, extract extractFunc) map[string]interface{} {
	dynamicValues := make(map[string]interface{})

	for _, extractor := range operators.Extractors {
		if !extractor.Internal {
			continue
		}
		if extractor.GetType() == DSLExtractor {
			typedResults := extractor.ExtractDSLTyped(data)
			if len(typedResults) == 1 {
				dynamicValues[extractor.Name] = typedResults[0]
			} else if len(typedResults) > 1 {
				dynamicValues[extractor.Name] = typedResults
			}
			continue
		}
		for match := range extract(data, extractor) {
			if _, ok := dynamicValues[extractor.Name]; !ok {
				dynamicValues[extractor.Name] = match
			}
		}
	}
	return dynamicValues
}

// MakeDynamicValuesCallback takes an input dynamic values map and calls
// the callback function with all variations of the data in input.
func MakeDynamicValuesCallback(input map[string]interface{}, iterateAllValues bool, callback func(map[string]interface{}) bool) {
	output := make(map[string]interface{}, len(input))

	if !iterateAllValues {
		for k, v := range input {
			if strs, ok := v.([]string); ok && len(strs) > 0 {
				output[k] = strs[0]
			} else {
				output[k] = v
			}
		}
		callback(output)
		return
	}

	inputIndex := make(map[string]int, len(input))
	var maxValue int
	for _, v := range input {
		if strs, ok := v.([]string); ok && len(strs) > maxValue {
			maxValue = len(strs)
		} else if maxValue == 0 {
			maxValue = 1
		}
	}

	for i := 0; i < maxValue; i++ {
		for k, v := range input {
			strs, ok := v.([]string)
			if !ok {
				output[k] = v
				continue
			}
			if len(strs) == 0 {
				continue
			}
			if len(strs) == 1 {
				output[k] = strs[0]
				continue
			}
			if gotIndex, ok := inputIndex[k]; !ok {
				inputIndex[k] = 0
				output[k] = strs[0]
			} else {
				newIndex := gotIndex + 1
				if newIndex >= len(strs) {
					output[k] = strs[len(strs)-1]
					continue
				}
				output[k] = strs[newIndex]
				inputIndex[k] = newIndex
			}
		}
		if callback(output) {
			return
		}
	}
}

// getExtractedValue takes array of extracted values if it only has one value
// then it is flattened and returned as a string else original type is returned
func getExtractedValue(values []string) interface{} {
	if len(values) == 1 {
		return values[0]
	} else {
		return values
	}
}

func getMatcherName(matcher *Matcher, matcherIndex int) string {
	if matcher.Name != "" {
		return matcher.Name
	} else {
		return matcher.Type + "-" + strconv.Itoa(matcherIndex+1) // making the index start from 1 to be more readable
	}
}
