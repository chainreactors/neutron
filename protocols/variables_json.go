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

func (variables *Variable) PreEvaluate(values map[string]interface{}) Variable {
	result := make(Variable, len(*variables))
	evaluated := make(map[string]interface{}, len(*variables))
	for key, value := range *variables {
		evaluated[key] = preEvaluateVariableValue(common.ToString(value), values, evaluated)
		result[key] = evaluated[key]
	}
	return result
}
