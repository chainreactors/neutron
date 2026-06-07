//go:build json
// +build json

package protocols

import (
	"sort"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/chainreactors/neutron/common"
)

type Variable map[string]interface{}

func (variables Variable) Len() int {
	return len(variables)
}

// Evaluate returns a finished map of variables based on set values. Each
// variable's own definition is evaluated, so a template variable shadows a
// builtin/runtime value of the same name (nuclei semantics).
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	combined := common.MergeMaps(values, nil)
	for _, key := range variables.sortedKeys() {
		evaluated := evaluateVariableValue(common.ToString((*variables)[key]), combined)
		result[key] = evaluated
		combined[key] = evaluated
	}
	return result
}

// WithFrozen returns a copy whose target-independent keys (as resolved by
// StableValues for one execution) have their definitions replaced by the frozen
// literal value. Evaluating the copy each request block then yields the same
// value, which is how random/static variables stay stable across blocks without
// any special handling inside Evaluate. Returns the receiver unchanged when
// there is nothing to freeze.
func (variables Variable) WithFrozen(frozen map[string]interface{}) Variable {
	if len(frozen) == 0 {
		return variables
	}
	result := make(Variable, len(variables))
	for key, value := range variables {
		if frozenValue, ok := frozen[key]; ok {
			result[key] = frozenValue
			continue
		}
		result[key] = value
	}
	return result
}

// StableValues freezes target-independent template variables for one execution.
func (variables *Variable) StableValues() map[string]interface{} {
	processing := make(map[string]interface{}, len(*variables))
	frozen := make(map[string]interface{}, len(*variables))
	empty := map[string]interface{}{}

	keys := variables.sortedKeys()
	for _, key := range keys {
		expr := common.ToString((*variables)[key])
		resolved, ok := preEvaluateVariableValue(expr, empty, processing)
		processing[key] = resolved
		if ok && isFrozenValue(resolved) {
			frozen[key] = resolved
		}
	}
	return frozen
}

func (variables *Variable) sortedKeys() []string {
	keys := make([]string, 0, len(*variables))
	for key := range *variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func evaluateVariableValue(expression string, values map[string]interface{}) string {
	result, err := common.Evaluate(expression, values)
	if err != nil {
		return expression
	}
	return result
}

func preEvaluateVariableValue(expression string, values, processing map[string]interface{}) (string, bool) {
	finalMap := common.MergeMaps(values, processing)
	if hasUnresolvedVariableDependency(expression, finalMap) {
		return expression, false
	}

	result, err := common.Evaluate(expression, finalMap)
	if err != nil {
		return expression, false
	}
	return result, true
}

func hasUnresolvedVariableDependency(expression string, values map[string]interface{}) bool {
	for _, dep := range expressionDependencies(expression) {
		value, ok := values[dep]
		if !ok {
			continue
		}
		if strings.Contains(common.ToString(value), common.ParenthesisOpen) {
			return true
		}
	}
	return false
}

func isFrozenValue(value interface{}) bool {
	data := common.ToString(value)
	return !strings.Contains(data, common.ParenthesisOpen)
}

func expressionDependencies(expression string) []string {
	expressions := templateExpressions(expression)
	if len(expressions) == 0 && strings.Contains(expression, "(") {
		expressions = []string{expression}
	}

	seen := make(map[string]struct{})
	var deps []string
	for _, expr := range expressions {
		compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, common.GetHelperFunctions())
		if err == nil {
			for _, dep := range compiled.Vars() {
				if _, ok := seen[dep]; ok {
					continue
				}
				seen[dep] = struct{}{}
				deps = append(deps, dep)
			}
			continue
		}
		if isIdentifier(expr) {
			if _, ok := seen[expr]; !ok {
				seen[expr] = struct{}{}
				deps = append(deps, expr)
			}
		}
	}
	return deps
}

func templateExpressions(data string) []string {
	var expressions []string
	for {
		open := strings.Index(data, common.ParenthesisOpen)
		if open < 0 {
			return expressions
		}
		start := open + len(common.ParenthesisOpen)
		close := strings.Index(data[start:], common.ParenthesisClose)
		if close < 0 {
			return expressions
		}
		end := start + close
		expressions = append(expressions, strings.TrimSpace(data[start:end]))
		data = data[end+len(common.ParenthesisClose):]
	}
}

func isIdentifier(data string) bool {
	if data == "" {
		return false
	}
	for i, ch := range data {
		if i == 0 {
			if ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' {
				continue
			}
			return false
		}
		if ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			continue
		}
		return false
	}
	return true
}
