package convert

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

// XrayPOC represents the xray POC YAML structure.
type XrayPOC struct {
	Name   string `yaml:"name"`
	Detail struct {
		Fingerprint struct {
			Name string `yaml:"name"`
			CPE  string `yaml:"cpe"`
		} `yaml:"fingerprint"`
	} `yaml:"detail"`
	Transport  string                 `yaml:"transport"`
	Set        map[string]interface{} `yaml:"set"`
	Payloads   XrayPayloadRoot        `yaml:"payloads"`
	Rules      map[string]XrayRule    `yaml:"rules"`
	Expression string                 `yaml:"expression"`
	Comments   CommentMetadata        `yaml:"-"`
}

// XrayPayloadRoot represents xray's row-oriented payload table.
type XrayPayloadRoot struct {
	Payloads map[string]map[string]interface{} `yaml:"payloads"`
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
	Expression string                 `yaml:"expression"`
	Output     map[string]interface{} `yaml:"output"`
}

// ConvertedTemplate represents the neutron template output.
type ConvertedTemplate struct {
	ID   string                 `yaml:"id"`
	Info map[string]interface{} `yaml:"info"`
	HTTP []ConvertedHTTPReq     `yaml:"http"`
}

// ConvertedHTTPReq represents one converted HTTP request block.
type ConvertedHTTPReq struct {
	Method            string                   `yaml:"method"`
	Path              []string                 `yaml:"path"`
	Headers           map[string]string        `yaml:"headers,omitempty"`
	Body              string                   `yaml:"body,omitempty"`
	MatchersCondition string                   `yaml:"matchers-condition,omitempty"`
	Matchers          []map[string]interface{} `yaml:"matchers,omitempty"`
	Redirects         bool                     `yaml:"redirects,omitempty"`
}

// Convert converts an xray POC YAML to a neutron template YAML.
func Convert(xrayYAML []byte) ([]byte, error) {
	if strings.TrimSpace(string(xrayYAML)) == "" {
		return nil, fmt.Errorf("empty xray yaml")
	}
	var poc XrayPOC
	if err := yaml.Unmarshal(xrayYAML, &poc); err != nil {
		return nil, fmt.Errorf("parse xray yaml: %w", err)
	}
	poc.Comments = extractComments(string(xrayYAML))
	return ConvertPOC(&poc)
}

// ConvertPOC converts a parsed xray POC to neutron template YAML.
func ConvertPOC(poc *XrayPOC) ([]byte, error) {
	if hasUnsupportedReverse(poc) {
		return nil, fmt.Errorf("unsupported xray reverse/oob callback semantics")
	}

	tmpl := map[string]interface{}{
		"id": sanitizeID(poc.Name),
		"info": map[string]interface{}{
			"name":     poc.Detail.Fingerprint.Name,
			"author":   "xray-converter",
			"severity": "info",
			"tags":     "neutron,xray,converted",
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

	ctx := newConversionContext(poc)
	httpReqs := buildHTTPBlocks(poc, ctx)
	if len(ctx.variables) > 0 {
		tmpl["variables"] = orderedVariables{values: ctx.variables, order: ctx.variableOrder}
	}
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
	method     string
	path       string
	headers    map[string]string
	body       string
	redirects  bool
	rules      []string
	exprs      []string
	extractors []interface{}
	payloads   map[string]interface{}
}

type conversionContext struct {
	variables     map[string]interface{}
	variableOrder []string
	variableAlias map[string]string
	payloads      map[string][]string
	runtimeVars   map[string]bool
}

func newConversionContext(poc *XrayPOC) *conversionContext {
	aliases := variableAliases(collectVariableNames(poc))
	variables, order := convertSetVariables(poc.Set, aliases)
	return &conversionContext{
		variables:     variables,
		variableOrder: order,
		variableAlias: aliases,
		payloads:      flattenPayloads(poc.Payloads, aliases),
		runtimeVars:   map[string]bool{},
	}
}

func (ctx *conversionContext) aliasName(name string) string {
	if ctx == nil || len(ctx.variableAlias) == 0 {
		return name
	}
	if alias, ok := ctx.variableAlias[name]; ok {
		return alias
	}
	return name
}

func (ctx *conversionContext) noSuffixVariables() map[string]bool {
	vars := map[string]bool{}
	for key := range ctx.variables {
		vars[key] = true
	}
	for key := range ctx.payloads {
		vars[key] = true
	}
	for key := range ctx.runtimeVars {
		vars[key] = true
	}
	return vars
}

func buildHTTPBlocks(poc *XrayPOC, ctx *conversionContext) []interface{} {
	topExpr := parseTopExpression(poc.Expression)

	keys := sortedKeys(poc.Rules)
	if topExpr != nil {
		seen := map[string]bool{}
		var ordered []string
		for _, name := range collectRuleNames(topExpr) {
			if seen[name] {
				continue
			}
			if _, ok := poc.Rules[name]; ok {
				ordered = append(ordered, name)
				seen[name] = true
			}
		}
		keys = ordered
	}

	preserveRuleOrder := topExpr != nil && hasANY(topExpr)
	groups, ruleGroup, ruleExprs := groupRules(poc, keys, ctx, preserveRuleOrder)
	if len(groups) == 0 {
		return nil
	}
	if branchBlocks := buildSingleRequestOrBranchBlocks(poc, topExpr, ruleExprs, groups); len(branchBlocks) > 0 {
		return branchBlocks
	}

	// Use req-condition when the top-level has any AND and there are
	// multiple groups. Handles both cross-group AND and within-group AND.
	if topExpr != nil && len(groups) > 1 && hasANY(topExpr) {
		return buildReqConditionBlocks(poc, groups, topExpr, ruleExprs, ruleGroup, ctx.noSuffixVariables())
	}

	if len(groups) == 1 {
		return buildSingleGroupBlocks(groups[0], poc.Expression, topExpr, ruleExprs)
	}

	return buildIndependentBlocks(groups)
}

func buildSingleRequestOrBranchBlocks(poc *XrayPOC, topExpr *TopExprNode, ruleExprs map[string]string, groups []*requestGroup) []interface{} {
	if topExpr == nil || topExpr.Type != "or" || len(topExpr.Children) == 0 {
		return nil
	}
	groupByRule := map[string]*requestGroup{}
	for _, g := range groups {
		for _, rule := range g.rules {
			groupByRule[rule] = g
		}
	}
	var out []interface{}
	for _, branch := range topExpr.Children {
		names := collectRuleNames(branch)
		requestRules := []string{}
		for _, name := range names {
			rule, ok := poc.Rules[name]
			if !ok {
				return nil
			}
			if hasXrayRequest(rule, strings.TrimSpace(rule.Expression)) {
				requestRules = append(requestRules, name)
			}
		}
		if len(requestRules) != 1 {
			return nil
		}
		g := groupByRule[requestRules[0]]
		if g == nil {
			return nil
		}
		combined := substituteRuleExprs(branch, ruleExprs)
		req := convertGroup(g.method, g.path, g.headers, g.body, g.redirects, []string{combined})
		if req == nil {
			continue
		}
		applyGroupExtras(req, g)
		out = append(out, req)
	}
	return out
}

func groupRules(poc *XrayPOC, keys []string, ctx *conversionContext, preserveRuleOrder bool) ([]*requestGroup, map[string]string, map[string]string) {
	var groups []*requestGroup
	groupIndex := map[string]int{}
	ruleGroup := map[string]string{}
	ruleExprs := map[string]string{}

	for _, ruleName := range keys {
		rule := poc.Rules[ruleName]
		rawExpr := strings.TrimSpace(rule.Expression)
		if rawExpr == "" {
			continue
		}
		expr := rawExpr
		if len(ctx.variableAlias) > 0 {
			expr = translateXrayExpression(rawExpr, ctx.variableAlias)
		}
		ruleExprs[ruleName] = expr
		if !hasXrayRequest(rule, rawExpr) {
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
		path = rewriteTemplatePlaceholders(path, ctx.variableAlias)
		path = normalizeRequestPath(path, ctx)
		headers := rewriteHeaderPlaceholders(rule.Request.Headers, ctx.variableAlias)
		body := rewriteTemplatePlaceholders(rule.Request.Body, ctx.variableAlias)

		key := method + ":" + path + ":" + headersKey(headers) + ":" + body
		if preserveRuleOrder {
			key = key + ":" + ruleName
		}
		ruleGroup[ruleName] = key
		extractors := outputExtractors(rule.Output, ctx)
		payloads := payloadsForRequest(path, headers, body, ctx.payloads)

		if idx, ok := groupIndex[key]; ok {
			groups[idx].rules = append(groups[idx].rules, ruleName)
			groups[idx].exprs = append(groups[idx].exprs, expr)
			groups[idx].extractors = append(groups[idx].extractors, extractors...)
			if len(payloads) > 0 && groups[idx].payloads == nil {
				groups[idx].payloads = map[string]interface{}{}
			}
			mergePayloads(groups[idx].payloads, payloads)
		} else {
			groupIndex[key] = len(groups)
			groups = append(groups, &requestGroup{
				method:     method,
				path:       path,
				headers:    headers,
				body:       body,
				redirects:  rule.Request.FollowRedirects,
				rules:      []string{ruleName},
				exprs:      []string{expr},
				extractors: extractors,
				payloads:   payloads,
			})
		}
	}
	return groups, ruleGroup, ruleExprs
}

func buildSingleGroupBlocks(g *requestGroup, topExprRaw string, topExpr *TopExprNode, ruleExprs map[string]string) []interface{} {
	var combined string
	if topExpr != nil {
		if needsRawTopExpression(topExprRaw) {
			if substituted, ok := substituteRuleCallsInExpression(topExprRaw, ruleExprs, nil, nil); ok {
				combined = substituted
			}
		}
		if combined == "" && len(g.rules) > 1 {
			combined = substituteRuleExprs(topExpr, ruleExprs)
		}
	} else if len(g.exprs) == 1 {
		combined = g.exprs[0]
	} else {
		parts := make([]string, len(g.exprs))
		for i, e := range g.exprs {
			parts[i] = "(" + e + ")"
		}
		combined = strings.Join(parts, " || ")
	}
	if combined == "" {
		if len(g.exprs) == 1 {
			combined = g.exprs[0]
		} else {
			parts := make([]string, len(g.exprs))
			for i, e := range g.exprs {
				parts[i] = "(" + e + ")"
			}
			combined = strings.Join(parts, " || ")
		}
	}

	req := convertGroup(g.method, g.path, g.headers, g.body, g.redirects, []string{combined})
	if req == nil {
		return nil
	}
	applyGroupExtras(req, g)
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
			applyGroupExtras(req, g)
			httpReqs = append(httpReqs, req)
		}
	}
	return httpReqs
}

func buildReqConditionBlocks(poc *XrayPOC, groups []*requestGroup, topExpr *TopExprNode, ruleExprs map[string]string, ruleGroup map[string]string, noSuffixVars map[string]bool) []interface{} {
	ruleReqIndex := map[string][]int{}
	requestOffset := 0
	for _, g := range groups {
		count := groupRequestCount(g)
		indices := make([]int, count)
		for j := 0; j < count; j++ {
			indices[j] = requestOffset + j + 1
		}
		for _, ruleName := range g.rules {
			ruleReqIndex[ruleName] = indices
		}
		requestOffset += count
	}
	lastIndex := requestOffset

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

	topDSL := buildReqConditionDSL(topExpr, poc.Expression, ruleDSLExprs, ruleReqIndex, lastIndex, noSuffixVars)

	var httpReqs []interface{}
	for i, g := range groups {
		req := map[string]interface{}{
			"method": g.method,
			"path":   []string{xrayTemplatePath(g.path)},
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
		applyGroupExtras(req, g)
		req["req-condition"] = true
		if i == len(groups)-1 {
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

func groupRequestCount(g *requestGroup) int {
	if g == nil || len(g.payloads) == 0 {
		return 1
	}
	max := 1
	for _, raw := range g.payloads {
		switch values := raw.(type) {
		case []string:
			if len(values) > max {
				max = len(values)
			}
		case []interface{}:
			if len(values) > max {
				max = len(values)
			}
		}
	}
	return max
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

var (
	placeholderRE      = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	slashPlaceholderRE = regexp.MustCompile(`/\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
)

func applyGroupExtras(req map[string]interface{}, g *requestGroup) {
	if len(g.extractors) > 0 {
		req["extractors"] = g.extractors
	}
	if len(g.payloads) > 0 {
		req["payloads"] = g.payloads
		req["attack"] = "pitchfork"
	}
}

func mergePayloads(dst, src map[string]interface{}) {
	if len(src) == 0 || dst == nil {
		return
	}
	for k, v := range src {
		dst[k] = v
	}
}

func payloadsForRequest(path string, headers map[string]string, body string, payloads map[string][]string) map[string]interface{} {
	if len(payloads) == 0 {
		return nil
	}
	used := map[string]bool{}
	collectPlaceholders(path, used)
	collectPlaceholders(body, used)
	for k, v := range headers {
		collectPlaceholders(k, used)
		collectPlaceholders(v, used)
	}
	if len(used) == 0 {
		return nil
	}
	out := map[string]interface{}{}
	for name := range used {
		values, ok := payloads[name]
		if !ok || len(values) == 0 {
			continue
		}
		out[name] = values
	}
	return out
}

func collectPlaceholders(s string, out map[string]bool) {
	for _, match := range placeholderRE.FindAllStringSubmatch(s, -1) {
		if len(match) > 1 {
			out[match[1]] = true
		}
	}
}

func rewriteHeaderPlaceholders(headers map[string]string, aliases map[string]string) map[string]string {
	if len(headers) == 0 || len(aliases) == 0 {
		return headers
	}
	rewritten := make(map[string]string, len(headers))
	for key, value := range headers {
		rewritten[rewriteTemplatePlaceholders(key, aliases)] = rewriteTemplatePlaceholders(value, aliases)
	}
	return rewritten
}

func rewriteTemplatePlaceholders(value string, aliases map[string]string) string {
	if value == "" || len(aliases) == 0 || !strings.Contains(value, "{{") {
		return value
	}
	return placeholderRE.ReplaceAllStringFunc(value, func(match string) string {
		parts := placeholderRE.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		if alias, ok := aliases[parts[1]]; ok {
			return "{{" + alias + "}}"
		}
		return match
	})
}

// xrayTemplatePath returns the full path expression for a converted xray template.
// xray POC paths are always absolute (relative to host root), so we use RootURL
// instead of BaseURL. This avoids doubled path segments when the scan target
// includes a path (e.g. http://host/app/) — BaseURL would include /app/ and the
// template path /app/login would produce /app/app/login.
func xrayTemplatePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return "{{RootURL}}" + path
	}
	return "{{BaseURL}}" + path
}

func normalizeRequestPath(path string, ctx *conversionContext) string {
	path = strings.TrimSpace(strings.TrimPrefix(path, "^"))
	path = strings.ReplaceAll(path, " ", "%20")
	path = strings.ReplaceAll(path, "#", "%23")
	if ctx == nil {
		return path
	}
	for _, match := range slashPlaceholderRE.FindAllStringSubmatch(path, -1) {
		if len(match) < 2 {
			continue
		}
		name := match[1]
		if ctx.runtimeVars[name] {
			path = strings.ReplaceAll(path, match[0], slashSafeRuntimePlaceholder(name))
			continue
		}
		if value, ok := ctx.variables[name].(string); ok && strings.HasPrefix(value, "/") {
			ctx.variables[name] = strings.TrimLeft(value, "/")
		}
	}
	return path
}

func slashSafeRuntimePlaceholder(name string) string {
	return fmt.Sprintf(`/{{trim_prefix(%s, "/")}}`, name)
}

func flattenPayloads(root XrayPayloadRoot, aliases map[string]string) map[string][]string {
	if len(root.Payloads) == 0 {
		return nil
	}
	rowKeys := make([]string, 0, len(root.Payloads))
	for k := range root.Payloads {
		rowKeys = append(rowKeys, k)
	}
	sortPayloadRows(rowKeys)

	result := map[string][]string{}
	for _, rowKey := range rowKeys {
		row := root.Payloads[rowKey]
		varKeys := make([]string, 0, len(row))
		for k := range row {
			varKeys = append(varKeys, k)
		}
		sort.Strings(varKeys)
		for _, varName := range varKeys {
			outName := aliasVariableName(varName, aliases)
			result[outName] = append(result[outName], normalizeXrayScalar(fmt.Sprint(row[varName])))
		}
	}
	return result
}

func sortPayloadRows(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		ni, okI := payloadRowNumber(keys[i])
		nj, okJ := payloadRowNumber(keys[j])
		if okI && okJ && ni != nj {
			return ni < nj
		}
		return keys[i] < keys[j]
	})
}

func payloadRowNumber(s string) (int, bool) {
	s = strings.TrimLeft(s, "pP")
	n, err := strconv.Atoi(s)
	return n, err == nil
}

type orderedVariables struct {
	values map[string]interface{}
	order  []string
}

func (v orderedVariables) MarshalYAML() (interface{}, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	seen := map[string]bool{}
	for _, key := range v.order {
		value, ok := v.values[key]
		if !ok {
			continue
		}
		seen[key] = true
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key})
		node.Content = append(node.Content, scalarYAMLNode(value))
	}
	keys := make([]string, 0, len(v.values))
	for key := range v.values {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key})
		node.Content = append(node.Content, scalarYAMLNode(v.values[key]))
	}
	return node, nil
}

func scalarYAMLNode(value interface{}) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(value)}
}

func convertSetVariables(set map[string]interface{}, aliases map[string]string) (map[string]interface{}, []string) {
	if len(set) == 0 {
		return nil, nil
	}
	vars := map[string]interface{}{}
	for key, raw := range set {
		switch raw.(type) {
		case map[string]interface{}, map[interface{}]interface{}, []interface{}:
			continue
		}
		value := strings.TrimSpace(fmt.Sprint(raw))
		if value == "" {
			continue
		}
		if key == "RootURL" && isRootURLSetExpression(value) {
			continue
		}
		outKey := aliasVariableName(key, aliases)
		vars[outKey] = translateXraySetExpression(value, aliases)
	}
	if _, ok := vars["randomstr"]; ok {
		if _, exists := vars["randstr"]; !exists {
			vars["randstr"] = "{{randomstr}}"
		}
	}
	if _, ok := vars["randomnum"]; ok {
		if _, exists := vars["randnum"]; !exists {
			vars["randnum"] = "{{randomnum}}"
		}
	}
	return vars, orderSetVariables(vars)
}

func isRootURLSetExpression(expr string) bool {
	compact := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(expr), " ", ""), "'", `"`)
	switch compact {
	case `response.url.scheme+"://"+response.url.domain`,
		`request.url.scheme+"://"+request.url.domain`,
		`response.url.scheme+"://"+response.url.host`,
		`request.url.scheme+"://"+request.url.host`:
		return true
	default:
		return false
	}
}

var neutronBuiltinVariableNames = map[string]bool{
	"BaseURL":  true,
	"RootURL":  true,
	"Hostname": true,
	"Host":     true,
	"Port":     true,
	"Path":     true,
	"File":     true,
	"Scheme":   true,
}

var neutronRuntimeVariableNames = map[string]bool{
	"all_headers":       true,
	"body":              true,
	"body_favicon_hash": true,
	"content_type":      true,
	"duration":          true,
	"favicon_content":   true,
	"favicon_hash":      true,
	"header":            true,
	"latency":           true,
	"matched":           true,
	"raw":               true,
	"status_code":       true,
	"title":             true,
}

func collectVariableNames(poc *XrayPOC) map[string]bool {
	names := map[string]bool{}
	if poc == nil {
		return names
	}
	for key, raw := range poc.Set {
		value := strings.TrimSpace(fmt.Sprint(raw))
		if key == "RootURL" && isRootURLSetExpression(value) {
			continue
		}
		names[key] = true
	}
	for _, rule := range poc.Rules {
		for key := range rule.Output {
			names[key] = true
		}
	}
	for _, row := range poc.Payloads.Payloads {
		for key := range row {
			names[key] = true
		}
	}
	return names
}

func variableAliases(names map[string]bool) map[string]string {
	if len(names) == 0 {
		return nil
	}
	used := map[string]bool{}
	for key := range names {
		used[key] = true
	}
	aliases := map[string]string{}
	for key := range names {
		if !isReservedVariableName(key) {
			continue
		}
		alias := "xray_" + key
		for i := 2; used[alias]; i++ {
			alias = fmt.Sprintf("xray_%s_%d", key, i)
		}
		aliases[key] = alias
		used[alias] = true
	}
	if len(aliases) == 0 {
		return nil
	}
	return aliases
}

func isReservedVariableName(name string) bool {
	if neutronBuiltinVariableNames[name] || neutronRuntimeVariableNames[name] {
		return true
	}
	switch name {
	case "true", "false", "nil":
		return true
	}
	for _, fn := range dsl.FunctionNames {
		if name == fn {
			return true
		}
	}
	return false
}

func aliasVariableName(name string, aliases map[string]string) string {
	if len(aliases) == 0 {
		return name
	}
	if alias, ok := aliases[name]; ok {
		return alias
	}
	return name
}

func translateXrayExpression(expr string, aliases map[string]string) string {
	if len(aliases) == 0 {
		return expr
	}
	ast, err := ParseToASTWithAliases(expr, aliases)
	if err != nil {
		return rewriteTemplatePlaceholders(expr, aliases)
	}
	return ast.String()
}

func translateXraySetExpression(expr string, aliases map[string]string) string {
	trimmed := strings.TrimSpace(expr)
	if strings.EqualFold(trimmed, "get404Path()") {
		return "{{rand_text_alphanumeric(16)}}"
	}
	if strings.Contains(trimmed, "{{") {
		return rewriteTemplatePlaceholders(normalizeXrayScalar(trimmed), aliases)
	}
	if base, ok := parseBFormat16Expression(trimmed); ok {
		return "{{hex_encode(" + aliasVariableName(base, aliases) + ")}}"
	}
	if ast, err := ParseToASTWithAliases(trimmed, aliases); err == nil {
		if ast.Type == dsl.NodeLiteral {
			return literalSetValue(ast.Value)
		}
		if ast.Type == dsl.NodeVariable && !strings.HasPrefix(trimmed, "request.") {
			if ast.String() != trimmed {
				return "{{" + ast.String() + "}}"
			}
			return normalizeXrayScalar(trimmed)
		}
		return "{{" + ast.String() + "}}"
	}
	replacer := strings.NewReplacer(
		"base64Decode(", "base64_decode(",
		"hexDecode(", "hex_decode(",
		"hex(", "hex_encode(",
	)
	translated := replacer.Replace(trimmed)
	if translated != trimmed && !strings.Contains(translated, "{{") {
		return "{{" + translated + "}}"
	}
	return normalizeXrayScalar(trimmed)
}

func literalSetValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func parseBFormat16Expression(expr string) (string, bool) {
	re := regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\.bformat\(\s*16\s*,\s*0\s*,\s*(?:""|'')\s*,\s*0\s*\)\s*$`)
	match := re.FindStringSubmatch(expr)
	if len(match) != 2 {
		return "", false
	}
	return match[1], true
}

func orderSetVariables(vars map[string]interface{}) []string {
	keys := make([]string, 0, len(vars))
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	visiting := map[string]bool{}
	visited := map[string]bool{}
	var order []string
	var visit func(string)
	visit = func(key string) {
		if visited[key] || visiting[key] {
			return
		}
		visiting[key] = true
		for _, dep := range variableDependencies(fmt.Sprint(vars[key]), vars) {
			visit(dep)
		}
		visiting[key] = false
		visited[key] = true
		order = append(order, key)
	}
	for _, key := range keys {
		visit(key)
	}
	return order
}

var variableIdentRE = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)

func variableDependencies(expr string, vars map[string]interface{}) []string {
	seen := map[string]bool{}
	var deps []string
	for _, ident := range variableIdentRE.FindAllString(expr, -1) {
		if _, ok := vars[ident]; ok && !seen[ident] {
			seen[ident] = true
			deps = append(deps, ident)
		}
	}
	sort.Strings(deps)
	return deps
}

func normalizeXrayScalar(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	tokens, err := xrayLex(value)
	if err == nil && len(tokens) >= 2 && tokens[0].Type == xTString && tokens[1].Type == xTEOF {
		return strings.TrimSpace(tokens[0].Val)
	}
	return value
}

type submatchSpec struct {
	Pattern   string
	Part      string
	GroupName string
}

func outputExtractors(output map[string]interface{}, ctx *conversionContext) []interface{} {
	if len(output) == 0 {
		return nil
	}
	sources := map[string]submatchSpec{}
	for _, name := range sortedOutputKeys(output) {
		raw := output[name]
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if specs := findSubmatchSpecs(expr); len(specs) > 0 {
			sources[name] = specs[0]
		}
	}

	var extractors []interface{}
	seen := map[string]bool{}
	for _, name := range sortedOutputKeys(output) {
		raw := output[name]
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if name == "" || expr == "" {
			continue
		}
		outName := ctx.aliasName(name)

		if spec, tempName, dslExpr, ok := resolveOutputTransform(expr, outName, sources); ok {
			ctx.runtimeVars[outName] = true
			ctx.runtimeVars[tempName] = true
			group := regexGroupIndex(spec.Pattern, spec.GroupName)
			if group == 0 {
				group = 1
			}

			regexKey := tempName + "\x00" + spec.Part + "\x00" + spec.Pattern + "\x00" + strconv.Itoa(group)
			if !seen[regexKey] {
				seen[regexKey] = true
				extractor := map[string]interface{}{
					"type":     "regex",
					"name":     tempName,
					"regex":    []string{spec.Pattern},
					"group":    group,
					"internal": true,
				}
				if spec.Part != "" && spec.Part != "body" {
					extractor["part"] = spec.Part
				}
				extractors = append(extractors, extractor)
			}

			dslKey := outName + "\x00dsl\x00" + dslExpr
			if !seen[dslKey] {
				seen[dslKey] = true
				extractors = append(extractors, map[string]interface{}{
					"type":     "dsl",
					"name":     outName,
					"dsl":      []string{dslExpr},
					"internal": true,
				})
			}
			continue
		}

		spec, ok := resolveOutputSpec(expr, sources)
		if ok {
			if spec.GroupName == "" {
				spec.GroupName = name
			}
			ctx.runtimeVars[outName] = true
			group := regexGroupIndex(spec.Pattern, spec.GroupName)
			if group == 0 {
				group = 1
			}
			key := outName + "\x00" + spec.Part + "\x00" + spec.Pattern + "\x00" + strconv.Itoa(group)
			if seen[key] {
				continue
			}
			seen[key] = true

			extractor := map[string]interface{}{
				"type":     "regex",
				"name":     outName,
				"regex":    []string{spec.Pattern},
				"group":    group,
				"internal": true,
			}
			if spec.Part != "" && spec.Part != "body" {
				extractor["part"] = spec.Part
			}
			extractors = append(extractors, extractor)

			if fallback, ok := outputFallbackLiteral(expr); ok {
				if ctx.variables == nil {
					ctx.variables = map[string]interface{}{}
				}
				if _, exists := ctx.variables[outName]; !exists {
					ctx.variables[outName] = normalizeXrayScalar(fallback)
				}
			}
			continue
		}

		if extractor := outputDSLExtractor(name, expr, ctx); extractor != nil {
			key := name + "\x00dsl\x00" + strings.Join(extractor["dsl"].([]string), "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			extractors = append(extractors, extractor)
		}
	}
	return extractors
}

func sortedOutputKeys(output map[string]interface{}) []string {
	keys := make([]string, 0, len(output))
	for key := range output {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func resolveOutputTransform(expr, name string, sources map[string]submatchSpec) (submatchSpec, string, string, bool) {
	source, group, dslExpr, ok := outputTransformExpression(expr, outputTempName(name))
	if !ok {
		return submatchSpec{}, "", "", false
	}
	spec, exists := sources[source]
	if !exists {
		return submatchSpec{}, "", "", false
	}
	spec.GroupName = group
	return spec, outputTempName(name), dslExpr, true
}

func outputTempName(name string) string {
	return name + "_raw"
}

func outputTransformExpression(expr, valueVar string) (string, string, string, bool) {
	tokens, err := xrayLex(expr)
	if err != nil || len(tokens) < 4 {
		return "", "", "", false
	}
	if tokens[len(tokens)-1].Type == xTEOF {
		tokens = tokens[:len(tokens)-1]
	}
	if len(tokens) < 4 || tokens[0].Type != xTIdent || tokens[1].Type != xTLParen {
		return "", "", "", false
	}

	fn := tokens[0].Val
	switch fn {
	case "replaceAll":
		source, group, next, ok := sourceRefOrStringAt(tokens, 2)
		if !ok || next+4 >= len(tokens) || tokens[next].Type != xTComma ||
			tokens[next+1].Type != xTString || tokens[next+2].Type != xTComma ||
			tokens[next+3].Type != xTString || tokens[next+4].Type != xTRParen ||
			next+5 != len(tokens) {
			return "", "", "", false
		}
		dslExpr := fmt.Sprintf("replace(%s, %s, %s)", valueVar, strconv.Quote(tokens[next+1].Val), strconv.Quote(tokens[next+3].Val))
		return source, group, dslExpr, true
	case "base64Decode":
		source, group, next, ok := sourceRefOrStringAt(tokens, 2)
		if !ok || next >= len(tokens) || tokens[next].Type != xTRParen || next+1 != len(tokens) {
			return "", "", "", false
		}
		return source, group, "base64_decode(" + valueVar + ")", true
	case "hexDecode":
		source, group, next, ok := sourceRefOrStringAt(tokens, 2)
		if !ok || next >= len(tokens) || tokens[next].Type != xTRParen || next+1 != len(tokens) {
			return "", "", "", false
		}
		return source, group, "hex_decode(" + valueVar + ")", true
	case "urlencode", "urlEncode", "url_encode":
		source, group, next, ok := sourceRefOrStringAt(tokens, 2)
		if !ok || next >= len(tokens) || tokens[next].Type != xTRParen || next+1 != len(tokens) {
			return "", "", "", false
		}
		return source, group, "url_encode(" + valueVar + ")", true
	default:
		return "", "", "", false
	}
}

func sourceRefOrStringAt(tokens []xToken, idx int) (string, string, int, bool) {
	if idx+1 < len(tokens) && tokens[idx].Type == xTIdent && tokens[idx].Val == "string" && tokens[idx+1].Type == xTLParen {
		source, group, next, ok := sourceRefAt(tokens, idx+2)
		if !ok || next >= len(tokens) || tokens[next].Type != xTRParen {
			return "", "", 0, false
		}
		return source, group, next + 1, true
	}
	return sourceRefAt(tokens, idx)
}

func sourceRefAt(tokens []xToken, idx int) (string, string, int, bool) {
	if idx+3 >= len(tokens) || tokens[idx].Type != xTIdent || tokens[idx+1].Type != xTLBracket ||
		(tokens[idx+2].Type != xTString && tokens[idx+2].Type != xTIdent) || tokens[idx+3].Type != xTRBracket {
		return "", "", 0, false
	}
	return tokens[idx].Val, tokens[idx+2].Val, idx + 4, true
}

func outputDSLExtractor(name, expr string, ctx *conversionContext) map[string]interface{} {
	if name == "" || expr == "" || strings.Contains(expr, "submatch") || strings.Contains(expr, "?") {
		return nil
	}
	ast, err := ParseToASTWithAliases(expr, ctx.variableAlias)
	if err != nil {
		return nil
	}
	if ast.Type == dsl.NodeLiteral {
		return nil
	}
	outName := ctx.aliasName(name)
	ctx.runtimeVars[outName] = true
	return map[string]interface{}{
		"type":     "dsl",
		"name":     outName,
		"dsl":      []string{ast.String()},
		"internal": true,
	}
}

func resolveOutputSpec(expr string, sources map[string]submatchSpec) (submatchSpec, bool) {
	if specs := findSubmatchSpecs(expr); len(specs) > 0 && specs[0].GroupName != "" {
		return specs[0], true
	}
	if source, group, ok := outputSourceReference(expr); ok {
		if spec, exists := sources[source]; exists {
			spec.GroupName = group
			return spec, true
		}
	}
	return submatchSpec{}, false
}

func findSubmatchSpecs(expr string) []submatchSpec {
	if specs := findConcatSubmatchSpecs(expr); len(specs) > 0 {
		return specs
	}
	tokens, err := xrayLex(expr)
	if err != nil {
		return nil
	}
	var specs []submatchSpec
	for i := 0; i+4 < len(tokens); i++ {
		if tokens[i].Type != xTString || tokens[i+1].Type != xTDot ||
			tokens[i+2].Type != xTIdent || !isSubmatchMethod(tokens[i+2].Val) ||
			tokens[i+3].Type != xTLParen {
			continue
		}
		closeIdx := findClosingParen(tokens, i+3)
		if closeIdx < 0 {
			continue
		}
		spec := submatchSpec{
			Pattern: tokens[i].Val,
			Part:    responsePartFromTokens(tokens[i+4 : closeIdx]),
		}
		if closeIdx+3 < len(tokens) && tokens[closeIdx+1].Type == xTLBracket &&
			(tokens[closeIdx+2].Type == xTString || tokens[closeIdx+2].Type == xTIdent) {
			spec.GroupName = tokens[closeIdx+2].Val
		}
		if spec.Part == "" {
			spec.Part = "body"
		}
		specs = append(specs, spec)
	}
	return specs
}

func findConcatSubmatchSpecs(expr string) []submatchSpec {
	re := regexp.MustCompile(`\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*string\((?:"([^"]*)"|'([^']*)')\)\s*\)\.(?:submatch|bsubmatch)\(([^)]*)\)`)
	match := re.FindStringSubmatch(expr)
	if len(match) == 0 {
		return nil
	}
	pattern := match[1]
	if pattern == "" {
		pattern = match[2]
	}
	return []submatchSpec{{
		Pattern: pattern,
		Part:    responsePartFromExpr(strings.TrimSpace(match[3])),
	}}
}

func responsePartFromExpr(expr string) string {
	tokens, err := xrayLex(expr)
	if err != nil {
		return "body"
	}
	return responsePartFromTokens(tokens)
}

func isSubmatchMethod(method string) bool {
	return method == "submatch" || method == "bsubmatch"
}

func findClosingParen(tokens []xToken, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(tokens); i++ {
		switch tokens[i].Type {
		case xTLParen:
			depth++
		case xTRParen:
			depth--
			if depth == 0 {
				return i
			}
		case xTEOF:
			return -1
		}
	}
	return -1
}

func responsePartFromTokens(tokens []xToken) string {
	if len(tokens) < 3 || tokens[0].Type != xTIdent || tokens[0].Val != "response" || tokens[1].Type != xTDot {
		return "body"
	}
	field := tokens[2].Val
	switch field {
	case "body", "body_string":
		return "body"
	case "raw_header", "headers":
		if len(tokens) >= 6 && tokens[3].Type == xTLBracket && tokens[4].Type == xTString {
			return headerVarName(tokens[4].Val)
		}
		return "header"
	case "content_type":
		return "content_type"
	case "title", "title_string":
		return "body"
	case "url":
		return "matched"
	default:
		return "body"
	}
}

func outputSourceReference(expr string) (string, string, bool) {
	tokens, err := xrayLex(expr)
	if err != nil {
		return "", "", false
	}
	for i := 0; i+3 < len(tokens); i++ {
		if tokens[i].Type == xTIdent && tokens[i+1].Type == xTLBracket &&
			(tokens[i+2].Type == xTString || tokens[i+2].Type == xTIdent) &&
			tokens[i+3].Type == xTRBracket {
			return tokens[i].Val, tokens[i+2].Val, true
		}
	}
	return "", "", false
}

func outputFallbackLiteral(expr string) (string, bool) {
	tokens, err := xrayLex(expr)
	if err != nil {
		return "", false
	}
	hasQuestion := false
	depth := 0
	for i, tok := range tokens {
		switch tok.Type {
		case xTLParen, xTLBracket:
			depth++
		case xTRParen, xTRBracket:
			if depth > 0 {
				depth--
			}
		case xTQuestion:
			if depth == 0 {
				hasQuestion = true
			}
		case xTColon:
			if hasQuestion && depth == 0 && i+1 < len(tokens) && tokens[i+1].Type == xTString {
				return tokens[i+1].Val, true
			}
		}
	}
	return "", false
}

func regexGroupIndex(pattern, groupName string) int {
	if groupName == "" {
		return 1
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return 1
	}
	for i, name := range compiled.SubexpNames() {
		if name == groupName {
			return i
		}
	}
	return 1
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
		"path":   []string{xrayTemplatePath(path)},
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

func hasXrayRequest(rule XrayRule, expr string) bool {
	if rule.Request.Method != "" ||
		rule.Request.Path != "" ||
		rule.Request.Body != "" ||
		len(rule.Request.Headers) > 0 ||
		rule.Request.FollowRedirects ||
		rule.Request.Cache {
		return true
	}
	return strings.Contains(expr, "response.")
}

func hasUnsupportedReverse(poc *XrayPOC) bool {
	for _, raw := range poc.Set {
		value := strings.TrimSpace(fmt.Sprint(raw))
		if strings.Contains(value, "newReverse()") || strings.Contains(value, "reverse.url") {
			return true
		}
	}
	for _, rule := range poc.Rules {
		if strings.Contains(rule.Expression, ".wait(") && strings.Contains(rule.Expression, "reverse") {
			return true
		}
		if strings.Contains(rule.Request.Path, "reverse") ||
			strings.Contains(rule.Request.Body, "reverse") {
			return true
		}
		for _, value := range rule.Request.Headers {
			if strings.Contains(value, "reverse") {
				return true
			}
		}
	}
	return false
}
