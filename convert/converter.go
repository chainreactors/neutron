package convert

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

// XrayPOC represents the xray POC YAML structure.
type XrayPOC struct {
	Name    string `yaml:"name"`
	Detail  struct {
		Fingerprint struct {
			Name string `yaml:"name"`
			CPE  string `yaml:"cpe"`
		} `yaml:"fingerprint"`
	} `yaml:"detail"`
	Transport  string              `yaml:"transport"`
	Rules      map[string]XrayRule `yaml:"rules"`
	Expression string              `yaml:"expression"`
	Comments   CommentMetadata     `yaml:"-"`
}

// CommentMetadata holds queries and URLs extracted from xray YAML comments.
type CommentMetadata struct {
	FofaQuery   []string
	HunterQuery []string
	ExampleURLs []string
}

// XrayRule represents one rule in an xray POC.
type XrayRule struct {
	Request struct {
		Method          string            `yaml:"method"`
		Path            string            `yaml:"path"`
		Headers         map[string]string `yaml:"headers"`
		Body            string            `yaml:"body"`
		FollowRedirects bool              `yaml:"follow_redirects"`
		Cache           bool              `yaml:"cache"`
	} `yaml:"request"`
	Expression string `yaml:"expression"`
}

// ConvertedTemplate represents the neutron template output.
type ConvertedTemplate struct {
	ID   string                 `yaml:"id"`
	Info map[string]interface{} `yaml:"info"`
	HTTP []ConvertedHTTPReq     `yaml:"http"`
}

// ConvertedHTTPReq represents one converted HTTP request block.
type ConvertedHTTPReq struct {
	Method            string                 `yaml:"method"`
	Path              []string               `yaml:"path"`
	Headers           map[string]string      `yaml:"headers,omitempty"`
	Body              string                 `yaml:"body,omitempty"`
	MatchersCondition string                 `yaml:"matchers-condition,omitempty"`
	Matchers          []map[string]interface{} `yaml:"matchers,omitempty"`
	Redirects         bool                   `yaml:"redirects,omitempty"`
}

// Convert converts an xray POC YAML to a neutron template YAML.
func Convert(xrayYAML []byte) ([]byte, error) {
	var poc XrayPOC
	if err := yaml.Unmarshal(xrayYAML, &poc); err != nil {
		return nil, fmt.Errorf("parse xray yaml: %w", err)
	}
	poc.Comments = extractComments(string(xrayYAML))
	return ConvertPOC(&poc)
}

// ConvertPOC converts a parsed xray POC to neutron template YAML.
func ConvertPOC(poc *XrayPOC) ([]byte, error) {
	tmpl := map[string]interface{}{
		"id": sanitizeID(poc.Name),
		"info": map[string]interface{}{
			"name":     poc.Detail.Fingerprint.Name,
			"author":   "xray-converter",
			"severity": "info",
			"tags":     "neutron,converted",
		},
	}

	// Build metadata
	metadata := map[string]interface{}{}
	if poc.Detail.Fingerprint.CPE != "" {
		metadata["cpe"] = poc.Detail.Fingerprint.CPE
	}
	if len(poc.Comments.FofaQuery) > 0 {
		if len(poc.Comments.FofaQuery) == 1 {
			metadata["fofa"] = poc.Comments.FofaQuery[0]
		} else {
			metadata["fofa"] = poc.Comments.FofaQuery
		}
	}
	if len(poc.Comments.HunterQuery) > 0 {
		if len(poc.Comments.HunterQuery) == 1 {
			metadata["hunter"] = poc.Comments.HunterQuery[0]
		} else {
			metadata["hunter"] = poc.Comments.HunterQuery
		}
	}
	if len(metadata) > 0 {
		info := tmpl["info"].(map[string]interface{})
		info["metadata"] = metadata
	}

	httpReqs := buildHTTPBlocks(poc)
	if len(httpReqs) > 0 {
		tmpl["http"] = httpReqs
	}

	out, err := yaml.Marshal(tmpl)
	if err != nil {
		return nil, err
	}
	out = appendGeneratedQueries(out, tmpl)
	return out, nil
}

type requestGroup struct {
	method    string
	path      string
	headers   map[string]string
	body      string
	redirects bool
	rules     []string
	exprs     []string
}

func buildHTTPBlocks(poc *XrayPOC) []interface{} {
	topExpr := parseTopExpression(poc.Expression)

	keys := sortedKeys(poc.Rules)
	if topExpr != nil {
		referenced := map[string]bool{}
		for _, name := range collectRuleNames(topExpr) {
			referenced[name] = true
		}
		var filtered []string
		for _, k := range keys {
			if referenced[k] {
				filtered = append(filtered, k)
			}
		}
		keys = filtered
	}

	groups, ruleGroup, ruleExprs := groupRules(poc, keys)
	if len(groups) == 0 {
		return nil
	}

	// Use req-condition when the top-level has any AND and there are
	// multiple groups. Handles both cross-group AND and within-group AND.
	if topExpr != nil && len(groups) > 1 && hasANY(topExpr) {
		return buildReqConditionBlocks(poc, groups, topExpr, ruleExprs, ruleGroup)
	}

	if len(groups) == 1 {
		return buildSingleGroupBlocks(groups[0], topExpr, ruleExprs)
	}

	return buildIndependentBlocks(groups)
}

func groupRules(poc *XrayPOC, keys []string) ([]*requestGroup, map[string]string, map[string]string) {
	var groups []*requestGroup
	groupIndex := map[string]int{}
	ruleGroup := map[string]string{}
	ruleExprs := map[string]string{}

	for _, ruleName := range keys {
		rule := poc.Rules[ruleName]
		expr := strings.TrimSpace(rule.Expression)
		if expr == "" {
			continue
		}
		method := rule.Request.Method
		if method == "" {
			method = "GET"
		}
		path := rule.Request.Path
		if path == "" {
			path = "/"
		}

		key := method + ":" + path + ":" + headersKey(rule.Request.Headers)
		ruleGroup[ruleName] = key
		ruleExprs[ruleName] = expr

		if idx, ok := groupIndex[key]; ok {
			groups[idx].rules = append(groups[idx].rules, ruleName)
			groups[idx].exprs = append(groups[idx].exprs, expr)
		} else {
			groupIndex[key] = len(groups)
			groups = append(groups, &requestGroup{
				method:    method,
				path:      path,
				headers:   rule.Request.Headers,
				body:      rule.Request.Body,
				redirects: rule.Request.FollowRedirects,
				rules:     []string{ruleName},
				exprs:     []string{expr},
			})
		}
	}
	return groups, ruleGroup, ruleExprs
}

func buildSingleGroupBlocks(g *requestGroup, topExpr *TopExprNode, ruleExprs map[string]string) []interface{} {
	var combined string
	if topExpr != nil && len(g.rules) > 1 {
		combined = substituteRuleExprs(topExpr, ruleExprs)
	} else if len(g.exprs) == 1 {
		combined = g.exprs[0]
	} else {
		parts := make([]string, len(g.exprs))
		for i, e := range g.exprs {
			parts[i] = "(" + e + ")"
		}
		combined = strings.Join(parts, " || ")
	}

	req := convertGroup(g.method, g.path, g.headers, g.body, g.redirects, []string{combined})
	if req == nil {
		return nil
	}
	return []interface{}{req}
}

func buildIndependentBlocks(groups []*requestGroup) []interface{} {
	var httpReqs []interface{}
	for _, g := range groups {
		var combined string
		if len(g.exprs) == 1 {
			combined = g.exprs[0]
		} else {
			parts := make([]string, len(g.exprs))
			for i, e := range g.exprs {
				parts[i] = "(" + e + ")"
			}
			combined = strings.Join(parts, " || ")
		}
		req := convertGroup(g.method, g.path, g.headers, g.body, g.redirects, []string{combined})
		if req != nil {
			httpReqs = append(httpReqs, req)
		}
	}
	return httpReqs
}

func buildReqConditionBlocks(poc *XrayPOC, groups []*requestGroup, topExpr *TopExprNode, ruleExprs map[string]string, ruleGroup map[string]string) []interface{} {
	ruleReqIndex := map[string]int{}
	for i, g := range groups {
		for _, ruleName := range g.rules {
			ruleReqIndex[ruleName] = i + 1
		}
	}
	lastIndex := len(groups)

	ruleDSLExprs := map[string]string{}
	for ruleName, expr := range ruleExprs {
		ast, err := ParseToAST(expr)
		if err != nil {
			ruleDSLExprs[ruleName] = expr
			continue
		}
		ast = TransformTitleToBodyRegex(ast)
		ruleDSLExprs[ruleName] = ast.String()
	}

	topDSL := buildReqConditionDSL(topExpr, ruleDSLExprs, ruleReqIndex, lastIndex)

	var httpReqs []interface{}
	for i, g := range groups {
		req := map[string]interface{}{
			"method": g.method,
			"path":   []string{"{{BaseURL}}" + g.path},
		}
		if len(g.headers) > 0 {
			req["headers"] = g.headers
		}
		if g.body != "" {
			req["body"] = g.body
		}
		if g.redirects {
			req["redirects"] = true
		}
		if i == len(groups)-1 {
			req["req-condition"] = true
			req["matchers"] = []interface{}{
				map[string]interface{}{
					"type": "dsl",
					"dsl":  []string{topDSL},
				},
			}
		}
		httpReqs = append(httpReqs, req)
	}
	return httpReqs
}

func headersKey(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+headers[k])
	}
	return strings.Join(parts, "&")
}

// appendGeneratedQueries loads the YAML as a neutron Template, calls ToQuery()
// to generate fofa-query/hunter-query from matchers, and writes them back.
func appendGeneratedQueries(yamlData []byte, tmpl map[string]interface{}) []byte {
	var t templates.Template
	if yaml.Unmarshal(yamlData, &t) != nil {
		return yamlData
	}
	if t.Compile(nil) != nil {
		for _, req := range t.GetRequests() {
			(&req.Operators).Compile()
			req.CompiledOperators = &req.Operators
		}
	}

	q := t.ToQuery()
	info, _ := tmpl["info"].(map[string]interface{})
	if info == nil {
		return yamlData
	}
	meta, _ := info["metadata"].(map[string]interface{})
	if meta == nil {
		meta = map[string]interface{}{}
	}

	changed := false
	for _, platform := range []string{"fofa", "hunter", "censys"} {
		r := q.Emit(platform)
		matcherQuery := ""
		if r != nil {
			matcherQuery = r.Query
		}

		// Merge: raw xray comment (metadata["fofa"]) || (matchers-generated query)
		rawComment, _ := meta[platform].(string)
		if rawComments, ok := meta[platform].([]interface{}); ok && len(rawComments) > 0 {
			var parts []string
			for _, c := range rawComments {
				if s, ok := c.(string); ok {
					parts = append(parts, s)
				}
			}
			rawComment = strings.Join(parts, " || ")
		}

		var combined string
		switch {
		case rawComment != "" && matcherQuery != "":
			combined = rawComment + " || (" + matcherQuery + ")"
		case rawComment != "":
			combined = rawComment
		case matcherQuery != "":
			combined = matcherQuery
		}

		if combined != "" {
			meta[platform+"-query"] = combined
			changed = true
		}
		// Remove the raw comment key — it's now merged into platform-query
		delete(meta, platform)
	}

	if changed {
		info["metadata"] = meta
		tmpl["info"] = info
		if out, err := yaml.Marshal(tmpl); err == nil {
			return out
		}
	}
	return yamlData
}

func convertGroup(method, path string, headers map[string]string, body string, redirects bool, exprs []string) map[string]interface{} {
	if len(exprs) == 0 {
		return nil
	}

	req := map[string]interface{}{
		"method": method,
		"path":   []string{"{{BaseURL}}" + path},
	}
	if len(headers) > 0 {
		req["headers"] = headers
	}
	if body != "" {
		req["body"] = body
	}
	if redirects {
		req["redirects"] = true
	}

	// Merge all expressions with OR to form a single combined expression.
	// This preserves the xray top-level "r0() || r1() || ..." semantics
	// so that weak rules (e.g. status==200 alone) don't become independent matchers.
	var combined string
	if len(exprs) == 1 {
		combined = exprs[0]
	} else {
		parts := make([]string, len(exprs))
		for i, e := range exprs {
			parts[i] = "(" + e + ")"
		}
		combined = strings.Join(parts, " || ")
	}

	result, err := ExprToMatchers(combined)
	if err != nil {
		req["matchers"] = []map[string]interface{}{
			{"type": "dsl", "dsl": []string{combined}},
		}
		return req
	}

	if result.MatchersCondition == "and" {
		req["matchers-condition"] = "and"
	}
	var matchers []interface{}
	for _, m := range result.Matchers {
		matchers = append(matchers, matcherToMap(m))
	}
	if len(matchers) > 0 {
		req["matchers"] = matchers
	}

	return req
}

func matcherToMap(m *operators.Matcher) map[string]interface{} {
	result := map[string]interface{}{"type": m.Type}

	if m.Part != "" && m.Part != "body" {
		result["part"] = m.Part
	}

	switch m.Type {
	case "word":
		result["words"] = m.Words
		if m.Condition != "" && m.Condition != "or" {
			result["condition"] = m.Condition
		}
		if m.CaseInsensitive {
			result["case-insensitive"] = true
		}
	case "status":
		result["status"] = m.Status
	case "regex":
		result["regex"] = m.Regex
	case "favicon":
		result["hash"] = m.Hash
	case "dsl":
		result["dsl"] = m.DSL
	}

	if m.Negative {
		result["negative"] = true
	}
	return result
}

// extractComments parses comment lines from raw xray YAML to find fofa/hunter queries and example URLs.
func extractComments(raw string) CommentMetadata {
	var m CommentMetadata
	inHunter := false

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			inHunter = false
			continue
		}
		content := strings.TrimSpace(trimmed[1:])
		lower := strings.ToLower(content)

		// Detect section headers
		if lower == "fofa query" || lower == "fofa_query" || strings.HasPrefix(lower, "fofa query") {
			inHunter = false
			continue
		}
		if lower == "hunter query" || strings.HasPrefix(lower, "hunter query") {
			inHunter = true
			continue
		}

		if content == "" {
			continue
		}

		// Example URLs
		if strings.HasPrefix(content, "http://") || strings.HasPrefix(content, "https://") {
			m.ExampleURLs = append(m.ExampleURLs, content)
			continue
		}

		// Query lines: app="X", body="X", product="X", title="X", header="X", etc.
		if isQueryLine(content) {
			if inHunter {
				m.HunterQuery = append(m.HunterQuery, content)
			} else {
				// Default to fofa (most comments are fofa)
				m.FofaQuery = append(m.FofaQuery, content)
			}
			continue
		}

		// Inline fofa comment like: # fofa: app="X"
		if strings.HasPrefix(lower, "fofa") {
			q := extractInlineQuery(content)
			if q != "" {
				m.FofaQuery = append(m.FofaQuery, q)
			}
			continue
		}
	}
	return m
}

func isQueryLine(s string) bool {
	prefixes := []string{
		"app=", "body=", "product=", "title=", "header=", "server=",
		"icon_hash=", "cert=", "protocol=", "banner=", "domain=",
		"app.name=", "web.body=", "web.title=",
	}
	lower := strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	// Pattern: something="value" or something="value" && something="value"
	if strings.Contains(s, `="`) && !strings.HasPrefix(s, "http") {
		return true
	}
	return false
}

func extractInlineQuery(s string) string {
	// "fofa: app="X"" or "fofa query: app="X""
	idx := strings.Index(s, ":")
	if idx < 0 {
		return ""
	}
	q := strings.TrimSpace(s[idx+1:])
	if q == "" {
		return ""
	}
	return q
}

func sanitizeID(name string) string {
	id := strings.TrimPrefix(name, "fingerprint-")
	id = strings.ReplaceAll(id, "--", "-")
	id = strings.ReplaceAll(id, " ", "-")
	return strings.ToLower(id)
}

func sortedKeys(rules map[string]XrayRule) []string {
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
