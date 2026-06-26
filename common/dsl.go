package common

import (
	"errors"
	"strconv"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/chainreactors/neutron/common/dsl"
)

const (
	// General marker (open/close)
	General = "§"
	// ParenthesisOpen marker - begin of a placeholder
	ParenthesisOpen = "{{"
	// ParenthesisClose marker - end of a placeholder
	ParenthesisClose = "}}"
)

var (
	HelperFunctions map[string]govaluate.ExpressionFunction
	FunctionNames   []string
	EvalError       = errors.New("failed to evaluate while adding headers to request")
)

func GetHelperFunctions() map[string]govaluate.ExpressionFunction {
	HelperFunctions = dsl.HelperFunctions()
	return HelperFunctions
}

func GetFunctionNames() []string {
	FunctionNames = dsl.DefaultFunctionNames()
	return FunctionNames
}

// Eval compiles the given expression and evaluate it with the given values preserving the return type
func Eval(expression string, values map[string]interface{}) (interface{}, error) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, GetHelperFunctions())
	if err != nil {
		return nil, err
	}
	return compiled.Evaluate(values)
}

// Evaluate checks if the match contains a dynamic variable, for each
// found one we will check if it's an expression and can
// be compiled, it will be evaluated and the results will be returned.
//
// The provided keys from finalValues will be used as variable names
// for substitution inside the expression.
func Evaluate(data string, base map[string]interface{}) (string, error) {
	return evaluate(data, base)
}

// EvaluateByte checks if the match contains a dynamic variable, for each
// found one we will check if it's an expression and can
// be compiled, it will be evaluated and the results will be returned.
//
// The provided keys from finalValues will be used as variable names
// for substitution inside the expression.
func EvaluateByte(data []byte, base map[string]interface{}) ([]byte, error) {
	finalData, err := evaluate(string(data), base)
	return []byte(finalData), err
}

func evaluate(data string, base map[string]interface{}) (string, error) {
	// replace simple placeholders (key => value) MarkerOpen + key + MarkerClose and General + key + General to value
	data = Replace(data, base)

	// expressions can be:
	// - simple: containing base values keys (variables)
	// - complex: containing helper functions [ + variables]
	// literals like {{2+2}} are not considered expressions
	expressions := FindExpressions(data, ParenthesisOpen, ParenthesisClose, base)
	for _, expression := range expressions {
		// replace variable placeholders with base values
		expression = Replace(expression, base)
		// turns expressions (either helper functions+base values or base values)
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expression, GetHelperFunctions())
		if err != nil {
			continue
		}
		result, err := compiled.Evaluate(base)
		if err != nil {
			continue
		}
		// replace incrementally
		data = ReplaceOne(data, expression, result)
	}
	return data, nil
}

// CoerceNumericStrings converts string values in a data map to float64 where
// possible. This allows govaluate's native arithmetic/comparison operators to
// work on values extracted by regex/DSL extractors (which always return strings).
// Non-numeric strings, non-string values, and known text keys are left untouched.
func CoerceNumericStrings(data map[string]interface{}) {
	for k, v := range data {
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		if n, err := strconv.ParseFloat(s, 64); err == nil {
			data[k] = n
		}
	}
}

// maxIterations to avoid infinite loop
const maxIterations = 250

func FindExpressions(data, OpenMarker, CloseMarker string, base map[string]interface{}) []string {
	var (
		iterations int
		exps       []string
	)
	for {
		// check if we reached the maximum number of iterations
		if iterations > maxIterations {
			break
		}
		iterations++
		// attempt to find open markers
		indexOpenMarker := strings.Index(data, OpenMarker)
		// exits if not found
		if indexOpenMarker < 0 {
			break
		}

		indexOpenMarkerOffset := indexOpenMarker + len(OpenMarker)

		shouldSearchCloseMarker := true
		closeMarkerFound := false
		innerData := data
		var potentialMatch string
		var indexCloseMarker, indexCloseMarkerOffset int
		skip := indexOpenMarkerOffset
		for shouldSearchCloseMarker {
			// attempt to find close marker
			indexCloseMarker = IndexAt(innerData, CloseMarker, skip)
			// if no close markers are found exit
			if indexCloseMarker < 0 {
				shouldSearchCloseMarker = false
				continue
			}
			indexCloseMarkerOffset = indexCloseMarker + len(CloseMarker)

			potentialMatch = innerData[indexOpenMarkerOffset:indexCloseMarker]
			if isExpression(potentialMatch, base) {
				closeMarkerFound = true
				shouldSearchCloseMarker = false
				exps = append(exps, potentialMatch)
			} else {
				skip = indexCloseMarkerOffset
			}
		}

		if closeMarkerFound {
			// move after the close marker
			data = data[indexCloseMarkerOffset:]
		} else {
			// move after the open marker
			data = data[indexOpenMarkerOffset:]
		}
	}
	return exps
}

func isExpression(data string, base map[string]interface{}) bool {
	if _, err := govaluate.NewEvaluableExpression(data); err == nil {
		if StringsContains(getFunctionsNames(base), data) {
			return true
		} else if StringsContains(GetFunctionNames(), data) {
			return true
		}
		return false
	}
	_, err := govaluate.NewEvaluableExpressionWithFunctions(data, GetHelperFunctions())
	return err == nil
}

func getFunctionsNames(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
