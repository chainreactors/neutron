package operators

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common"
)

// jsonPath is a compiled mini-jq expression. We deliberately accept ONLY the
// path-access subset of jq syntax that nuclei templates actually use in the
// wild:
//
//	.            — identity (whole document)
//	.field       — object field
//	.a.b.c       — nested field
//	.field[]     — iterate over an array/object field's elements
//	.[]          — iterate over the root array/object
//
// Anything more expressive (pipes, filters, select(), map(), constructors,
// arithmetic) is rejected at compile time with a clear error so users can
// rewrite the template or know exactly what's unsupported. This avoids
// silently swallowing complex expressions while keeping the dependency
// footprint zero — gojq lives in the optional operators/full/ submodule and
// can be opted into by `import _ ".../operators/full"`, which re-registers
// the "json" handler on top of this default mini-jq one.
type jsonPath struct {
	steps []jsonStep
	raw   string
}

// jsonStep is one segment of a path. Either a named field (kind=fieldStep,
// name set) or an array/object iterator (kind=iterStep).
type jsonStep struct {
	kind jsonStepKind
	name string
}

type jsonStepKind int

const (
	fieldStep jsonStepKind = iota + 1
	iterStep
)

func init() {
	// Register the zero-dependency mini-jq JSON extractor by default. The
	// optional operators/full/ submodule (gojq-backed) re-registers the same
	// "json" key on import — last init wins, so explicit full import gives
	// the gojq superset without any change here.
	RegisterExtractorType("json", JSONExtractor, compileJSONExtractor, extractJSON)
}

func compileJSONExtractor(e *Extractor) error {
	compiled := make([]*jsonPath, 0, len(e.JSON))
	for _, query := range e.JSON {
		p, err := compileJSONPath(query)
		if err != nil {
			return fmt.Errorf("could not compile json extractor: %w", err)
		}
		compiled = append(compiled, p)
	}
	e.SetCompiledData(compiled)
	return nil
}

// ExtractJSON is a thin convenience wrapper around the registered "json"
// extractor handler. Protocol implementations that want to switch on extractor
// type explicitly (rather than going through ExtractWithHandler) can call this
// to keep the dispatch matrix symmetric with ExtractRegex / ExtractKval /
// ExtractDSL. When the optional operators/full/ submodule is imported, this
// reaches gojq through the registered handler exactly the same way.
func (e *Extractor) ExtractJSON(corpus string) map[string]struct{} {
	return e.ExtractWithHandler(corpus, nil)
}

func extractJSON(e *Extractor, corpus string, _ map[string]interface{}) map[string]struct{} {
	results := make(map[string]struct{})

	var jsonObj interface{}
	if err := json.Unmarshal([]byte(corpus), &jsonObj); err != nil {
		return results
	}

	compiled, ok := e.GetCompiledData().([]*jsonPath)
	if !ok {
		return results
	}
	for _, path := range compiled {
		for _, v := range path.run(jsonObj) {
			var result string
			if res, err := common.JSONScalarToString(v); err == nil {
				result = res
			} else if res, err := json.Marshal(v); err == nil {
				result = string(res)
			} else {
				result = common.ToString(v)
			}
			results[result] = struct{}{}
		}
	}
	return results
}

// compileJSONPath parses a jq-subset expression. Returns an error listing
// the offending token for anything outside the supported grammar.
func compileJSONPath(expr string) (*jsonPath, error) {
	raw := expr
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty jq expression")
	}
	// Disallow obvious jq features we don't implement so failure is loud, not
	// silently wrong. Keep the check coarse — the parser below catches the
	// rest.
	for _, banned := range []string{"|", "select(", "map(", "[]?", "?", ",", "+", "-", "*", "/"} {
		if strings.Contains(expr, banned) {
			return nil, fmt.Errorf("unsupported jq construct %q in expression %q; neutron's json extractor accepts only .field, .a.b, .field[], .[]", banned, raw)
		}
	}
	if !strings.HasPrefix(expr, ".") {
		return nil, fmt.Errorf("jq expression must start with '.': %q", raw)
	}

	p := &jsonPath{raw: raw}
	// Special case: "." alone is identity, no steps.
	if expr == "." {
		return p, nil
	}

	i := 0
	for i < len(expr) {
		switch expr[i] {
		case '.':
			i++
			// .[] at root or after a step: array/object iteration.
			if i < len(expr) && expr[i] == '[' {
				if i+1 >= len(expr) || expr[i+1] != ']' {
					return nil, fmt.Errorf("expected ']' after '[' in %q at offset %d", raw, i)
				}
				p.steps = append(p.steps, jsonStep{kind: iterStep})
				i += 2
				continue
			}
			// Otherwise parse a field name: [A-Za-z0-9_]+
			start := i
			for i < len(expr) {
				c := expr[i]
				if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
					i++
					continue
				}
				break
			}
			if start == i {
				return nil, fmt.Errorf("expected field name after '.' in %q at offset %d", raw, start)
			}
			p.steps = append(p.steps, jsonStep{kind: fieldStep, name: expr[start:i]})
		case '[':
			// field[]  — iterator immediately after a field, no dot.
			if i+1 >= len(expr) || expr[i+1] != ']' {
				return nil, fmt.Errorf("expected ']' after '[' in %q at offset %d", raw, i)
			}
			p.steps = append(p.steps, jsonStep{kind: iterStep})
			i += 2
		default:
			return nil, fmt.Errorf("unexpected character %q in jq expression %q at offset %d", expr[i], raw, i)
		}
	}
	return p, nil
}

// run walks `root` through the compiled steps and returns the leaf values.
// Object-iteration yields the map's values (jq order is unspecified anyway).
// Missing fields produce no results rather than errors — mirrors gojq behavior
// on the kinds of input nuclei feeds it.
func (p *jsonPath) run(root interface{}) []interface{} {
	current := []interface{}{root}
	for _, step := range p.steps {
		var next []interface{}
		for _, v := range current {
			switch step.kind {
			case fieldStep:
				m, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				if item, ok := m[step.name]; ok {
					next = append(next, item)
				}
			case iterStep:
				switch t := v.(type) {
				case []interface{}:
					next = append(next, t...)
				case map[string]interface{}:
					for _, val := range t {
						next = append(next, val)
					}
				}
			}
		}
		current = next
		if len(current) == 0 {
			return nil
		}
	}
	return current
}
