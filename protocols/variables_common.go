package protocols

import (
	"regexp"
	"strings"

	"github.com/chainreactors/neutron/common"
)

var variableDependencyRE = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)

func evaluateVariableValue(expression string, values, processing map[string]interface{}) string {
	finalMap := common.MergeMaps(values, processing)
	result, err := common.Evaluate(expression, finalMap)
	if err != nil {
		return expression
	}
	return result
}

func preEvaluateVariableValue(expression string, values, processing map[string]interface{}) string {
	finalMap := common.MergeMaps(values, processing)
	if hasUnresolvedVariableDependency(expression, finalMap) {
		return expression
	}

	result, err := common.Evaluate(expression, finalMap)
	if err != nil {
		return expression
	}
	return result
}

func hasUnresolvedVariableDependency(expression string, values map[string]interface{}) bool {
	if !strings.Contains(expression, common.ParenthesisOpen) {
		return false
	}
	for _, expr := range common.FindExpressions(expression, common.ParenthesisOpen, common.ParenthesisClose, values) {
		for _, ident := range variableDependencyRE.FindAllString(expr, -1) {
			value, ok := values[ident]
			if !ok {
				continue
			}
			if strings.Contains(common.ToString(value), common.ParenthesisOpen) {
				return true
			}
		}
	}
	return false
}
