package operators

import (
	"fmt"

	"github.com/chainreactors/neutron/common/dsl"
)

func (m *Matcher) ToQuery(e dsl.Emitter) *dsl.Result {
	r := &dsl.Result{}
	part := dsl.NormalizePart(m.Part)

	switch m.matcherType {
	case WordsMatcher:
		r.Query = matcherWordsToQuery(m, e, part, r)
	case StatusMatcher:
		r.Query = matcherStatusToQuery(m, e, r)
	case FaviconMatcher:
		r.Query = matcherFaviconToQuery(m, e, r)
	case DSLMatcher:
		r.Query = matcherDSLToQuery(m, e, r)
	case RegexMatcher:
		r.Errors = append(r.Errors, "regex matcher cannot be converted to search query")
	case BinaryMatcher:
		r.Errors = append(r.Errors, "binary matcher cannot be converted to search query")
	case SizeMatcher:
		r.Errors = append(r.Errors, "size matcher cannot be converted to search query")
	default:
		r.Errors = append(r.Errors, fmt.Sprintf("unknown matcher type: %d", m.matcherType))
	}

	if m.Negative && r.Query != "" {
		r.Query = e.Not(r.Query)
	}
	return r
}

func (o *Operators) ToQuery(e dsl.Emitter) *dsl.Result {
	r := &dsl.Result{}
	var clauses []string

	for _, m := range o.Matchers {
		mr := m.ToQuery(e)
		r.Warnings = append(r.Warnings, mr.Warnings...)
		r.Errors = append(r.Errors, mr.Errors...)
		if mr.Query != "" {
			clauses = append(clauses, mr.Query)
		}
	}

	if len(clauses) == 0 {
		return r
	}

	if o.matchersCondition == ANDCondition {
		r.Query = e.And(clauses...)
	} else {
		r.Query = e.Or(clauses...)
	}
	return r
}

func matcherWordsToQuery(m *Matcher, e dsl.Emitter, part string, r *dsl.Result) string {
	field := e.Field(part)
	clauses := make([]string, 0, len(m.Words))

	if part == "all" {
		for _, word := range m.Words {
			bodyQ := e.Contains(e.Field("body"), word)
			headerQ := e.Contains(e.Field("all_headers"), word)
			clauses = append(clauses, e.Group(e.Or(bodyQ, headerQ)))
		}
	} else {
		for _, word := range m.Words {
			clauses = append(clauses, e.Contains(field, word))
		}
	}

	if len(clauses) == 0 {
		return ""
	}
	if len(clauses) == 1 {
		return clauses[0]
	}
	if m.condition == ANDCondition {
		return e.Group(e.And(clauses...))
	}
	return e.Group(e.Or(clauses...))
}

func matcherStatusToQuery(m *Matcher, e dsl.Emitter, r *dsl.Result) string {
	clauses := make([]string, 0, len(m.Status))
	for _, code := range m.Status {
		clauses = append(clauses, e.StatusCode(code))
	}
	if len(clauses) <= 1 {
		return joinOr(clauses)
	}
	return e.Group(e.Or(clauses...))
}

func joinOr(clauses []string) string {
	if len(clauses) == 0 {
		return ""
	}
	return clauses[0]
}

func matcherFaviconToQuery(m *Matcher, e dsl.Emitter, r *dsl.Result) string {
	clauses := make([]string, 0, len(m.Hash))
	for _, hash := range m.Hash {
		q, err := e.FaviconHash(hash)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
			continue
		}
		clauses = append(clauses, q)
	}
	if len(clauses) == 0 {
		return ""
	}
	return e.Or(clauses...)
}

func matcherDSLToQuery(m *Matcher, e dsl.Emitter, r *dsl.Result) string {
	clauses := make([]string, 0, len(m.DSL))
	for _, expr := range m.DSL {
		node, err := dsl.Parse(expr)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("failed to parse DSL %q: %v", expr, err))
			continue
		}
		dr := dsl.Generate(node, e)
		r.Warnings = append(r.Warnings, dr.Warnings...)
		r.Errors = append(r.Errors, dr.Errors...)
		if dr.Query != "" {
			clauses = append(clauses, dr.Query)
		}
	}

	if len(clauses) == 0 {
		return ""
	}
	if m.condition == ANDCondition {
		return e.And(clauses...)
	}
	return e.Or(clauses...)
}
