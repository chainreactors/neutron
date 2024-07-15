//go:build json
// +build json

package protocols

import (
	"github.com/chainreactors/neutron/common"
)

type Variable map[string]interface{}

func (variables Variable) Len() int {
	return len(variables)
}

// Evaluate returns a finished map of variables based on set values
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range *variables {
		result[key] = evaluateVariableValue(common.ToString(value), values, result)
	}
	return result
}

// evaluateVariableValue expression and returns final value
func evaluateVariableValue(expression string, values, processing map[string]interface{}) string {
	finalMap := common.MergeMaps(values, processing)

	result, err := common.Evaluate(expression, finalMap)
	if err != nil {
		return expression
	}
	return result
}
