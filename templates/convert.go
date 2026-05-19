package templates

import (
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
)

type QueryResult struct {
	Query    string
	Source   string // "metadata", "matcher", or "combined"
	Warnings []string
	Errors   []string
}

func (r *QueryResult) HasErrors() bool { return len(r.Errors) > 0 }

func (t *Template) ToQuery(platform string) *QueryResult {
	metaQ := t.metadataQuery(platform)
	matcherR := t.matcherQuery(platform)

	var clauses []string
	if metaQ != "" {
		clauses = append(clauses, metaQ)
	}
	if matcherR.Query != "" {
		clauses = append(clauses, matcherR.Query)
	}

	result := &QueryResult{
		Warnings: matcherR.Warnings,
		Errors:   matcherR.Errors,
	}

	switch {
	case len(clauses) == 0:
		result.Source = matcherR.Source
	case metaQ != "" && matcherR.Query != "":
		emitter, ok := dsl.GetEmitter(platform)
		if ok {
			result.Query = emitter.Or(clauses...)
		} else {
			result.Query = strings.Join(clauses, " || ")
		}
		result.Source = "combined"
	case metaQ != "":
		result.Query = metaQ
		result.Source = "metadata"
	default:
		result.Query = matcherR.Query
		result.Source = "matcher"
	}
	return result
}

func (t *Template) metadataQuery(platform string) string {
	if t.Info.Metadata == nil {
		return ""
	}

	key := platform + "-query"
	val, ok := t.Info.Metadata[key]
	if !ok {
		return ""
	}

	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, " || ")
	case []string:
		parts := make([]string, 0, len(v))
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, " || ")
	}
	return ""
}

func (t *Template) matcherQuery(platform string) *QueryResult {
	emitter, ok := dsl.GetEmitter(platform)
	if !ok {
		return &QueryResult{
			Errors: []string{fmt.Sprintf("unknown platform: %s", platform)},
		}
	}

	requests := t.GetRequests()
	if len(requests) == 0 {
		return &QueryResult{Errors: []string{"no HTTP requests in template"}}
	}

	var allClauses []string
	result := &QueryResult{Source: "matcher"}

	for _, req := range requests {
		r := req.Operators.ToQuery(emitter)
		result.Warnings = append(result.Warnings, r.Warnings...)
		result.Errors = append(result.Errors, r.Errors...)
		if r.Query != "" {
			allClauses = append(allClauses, r.Query)
		}
	}

	if len(allClauses) == 1 {
		result.Query = allClauses[0]
	} else if len(allClauses) > 1 {
		result.Query = emitter.Or(allClauses...)
	}

	return result
}
