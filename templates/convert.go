package templates

import (
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
)

func (t *Template) ToQuery() *dsl.Query {
	q := dsl.NewQuery()

	// metadata queries (fofa-query, hunter-query, shodan-query, censys-query)
	if t.Info.Metadata != nil {
		for _, platform := range []string{"fofa", "hunter", "shodan", "censys"} {
			if metas := extractMetadataQueries(t.Info.Metadata, platform); len(metas) > 0 {
				q.Metadata[platform] = metas
			}
		}
	}

	// matcher-derived AST
	requests := t.GetRequests()
	if len(requests) == 0 {
		return q
	}

	var nodes []*dsl.Node
	for _, req := range requests {
		rq := req.Operators.ToQuery()
		q.Warnings = append(q.Warnings, rq.Warnings...)
		q.Errors = append(q.Errors, rq.Errors...)
		if rq.Node != nil {
			nodes = append(nodes, rq.Node)
		}
	}

	if len(nodes) == 1 {
		q.Node = nodes[0]
	} else if len(nodes) > 1 {
		result := nodes[0]
		for _, n := range nodes[1:] {
			result = dsl.BinaryOp("||", result, n)
		}
		q.Node = result
	}

	return q
}

func extractMetadataQueries(metadata map[string]interface{}, platform string) []string {
	val, ok := metadata[platform+"-query"]
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []interface{}:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					result = append(result, s)
				}
			}
		}
		return result
	case []string:
		var result []string
		for _, s := range v {
			if s = strings.TrimSpace(s); s != "" {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
