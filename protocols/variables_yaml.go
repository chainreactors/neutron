//go:build !json
// +build !json

package protocols

import (
	"fmt"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/chainreactors/neutron/common"
	"gopkg.in/yaml.v3"
)

type InsertionOrderedStringMap struct {
	keys   []string `yaml:"-"`
	values map[string]interface{}
}

func NewEmptyInsertionOrderedStringMap(size int) *InsertionOrderedStringMap {
	return &InsertionOrderedStringMap{
		keys:   make([]string, 0, size),
		values: make(map[string]interface{}, size),
	}
}

func NewInsertionOrderedStringMap(stringMap map[string]interface{}) *InsertionOrderedStringMap {
	result := NewEmptyInsertionOrderedStringMap(len(stringMap))

	for k, v := range stringMap {
		result.Set(k, v)
	}
	return result
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) Len() int {
	return len(insertionOrderedStringMap.values)
}

// UnmarshalYAML unmarshals YAML data into the map, maintaining the insertion order
func (insertionOrderedStringMap *InsertionOrderedStringMap) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected a mapping node, got %d", node.Kind)
	}
	insertionOrderedStringMap.values = make(map[string]interface{})
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1].Value
		insertionOrderedStringMap.Set(key, value)
	}
	return nil
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) ForEach(fn func(key string, data interface{})) {
	for _, key := range insertionOrderedStringMap.keys {
		fn(key, insertionOrderedStringMap.values[key])
	}
}

func (insertionOrderedStringMap *InsertionOrderedStringMap) Set(key string, value interface{}) {
	_, present := insertionOrderedStringMap.values[key]
	insertionOrderedStringMap.values[key] = value
	if !present {
		insertionOrderedStringMap.keys = append(insertionOrderedStringMap.keys, key)
	}
}

type Variable struct {
	InsertionOrderedStringMap `yaml:"-" json:"-"`
}

// Evaluate returns a finished map of variables based on set values. Each
// variable's own definition is evaluated, so a template variable shadows a
// builtin/runtime value of the same name (nuclei semantics).
func (variables *Variable) Evaluate(values map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, variables.Len())
	combined := common.MergeMaps(values, nil)
	variables.ForEach(func(key string, value interface{}) {
		evaluated := evaluateVariableValue(common.ToString(value), combined)
		result[key] = evaluated
		combined[key] = evaluated
	})
	return result
}

// StableValues evaluates variables against an empty context and returns only
// those whose value is fully resolved (no remaining {{...}} templates) and
// whose dependencies are all themselves resolved. Used by the executer to
// pre-compute random/static values once per scan execution.
func (variables *Variable) StableValues() map[string]interface{} {
	processing := make(map[string]interface{}, variables.Len())
	frozen := make(map[string]interface{}, variables.Len())
	empty := map[string]interface{}{}

	variables.ForEach(func(key string, value interface{}) {
		expr := common.ToString(value)
		resolved, ok := preEvaluateVariableValue(expr, empty, processing)
		processing[key] = resolved
		if ok && !strings.Contains(common.ToString(resolved), common.ParenthesisOpen) {
			frozen[key] = resolved
		}
	})
	return frozen
}

func (variables *Variable) UnmarshalYAML(unmarshal func(interface{}) error) error {
	variables.InsertionOrderedStringMap = InsertionOrderedStringMap{}
	return unmarshal(&variables.InsertionOrderedStringMap)
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
