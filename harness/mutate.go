package harness

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/dsl"
	"github.com/chainreactors/neutron/convert"
)

var placeholderRE = regexp.MustCompile(`\{\{\s*([^}]+?)\s*\}\}`)

func BuildScenarios(poc *convert.XrayPOC, opt Options) ([]*Scenario, error) {
	if opt.MaxDelay == 0 {
		opt.MaxDelay = DefaultMaxDelay
	}
	values, wildcards := initialValues(poc)
	setExprs := setExpressions(poc)
	for k, v := range selectPayloadRow(poc) {
		values[k] = v
		delete(wildcards, k)
	}

	ruleSets := scenarioRuleSets(poc)
	if len(ruleSets) == 0 {
		return nil, fmt.Errorf("no runnable rule scenarios")
	}

	var scenarios []*Scenario
	for i, rules := range ruleSets {
		sc := &Scenario{
			Name:      fmt.Sprintf("scenario-%d", i+1),
			Rules:     rules,
			Variables: cloneStringMap(values),
		}
		scWildcards := cloneBoolMap(wildcards)
		if hasTopLevelUnsupported(poc) {
			sc.Unsupported = append(sc.Unsupported, "top-level non-rule or negated expressions are not modeled by harness v1")
		}
		for _, ruleName := range rules {
			rule, ok := poc.Rules[ruleName]
			if !ok {
				continue
			}
			applyExpressionVariableHints(rule.Expression, sc.Variables)
		}
		for _, ruleName := range rules {
			rule, ok := poc.Rules[ruleName]
			if !ok {
				continue
			}
			route, unsupported := buildRoute(ruleName, &rule, sc.Variables, scWildcards, setExprs, opt)
			sc.Unsupported = append(sc.Unsupported, unsupported...)
			if route != nil {
				sc.Routes = append(sc.Routes, route)
			}
		}
		sc.Unsupported = uniqueStrings(sc.Unsupported)
		scenarios = append(scenarios, sc)
	}
	return scenarios, nil
}

func buildRoute(ruleName string, rule *convert.XrayRule, values map[string]string, wildcards map[string]bool, setExprs map[string]string, opt Options) (*Route, []string) {
	routeValues := cloneStringMap(values)
	method := rule.Request.Method
	if method == "" {
		method = "GET"
	}
	reqPath := rule.Request.Path
	if reqPath == "" {
		reqPath = "/"
	}
	reqPath = strings.TrimSpace(strings.TrimPrefix(reqPath, "^"))

	resp, unsupported := responseForRule(rule, opt, routeValues)
	outputUnsupported := applyOutputs(rule.Output, resp, values)
	unsupported = append(unsupported, outputUnsupported...)

	pathPattern, err := templateRegexp(reqPath, values, wildcards, true)
	if err != nil {
		unsupported = append(unsupported, "request path pattern unsupported: "+err.Error())
		return nil, unsupported
	}

	route := &Route{
		Rule:         ruleName,
		Method:       strings.ToUpper(method),
		PathTemplate: reqPath,
		Path:         pathPattern,
		Headers:      map[string]*Pattern{},
		Response:     resp,
	}
	ruleCopy := *rule
	route.Build = func(runtimeVars map[string]string) (*ResponseSpec, map[string]string) {
		merged := cloneStringMap(routeValues)
		for k, v := range runtimeVars {
			merged[k] = v
		}
		deriveSetVariables(setExprs, merged)
		dynamicResp, _ := responseForRule(&ruleCopy, opt, merged)
		outputValues := cloneStringMap(merged)
		_ = applyOutputs(ruleCopy.Output, dynamicResp, outputValues)
		outputs := map[string]string{}
		for k, v := range outputValues {
			if merged[k] != v {
				outputs[k] = v
			}
		}
		return dynamicResp, outputs
	}
	if strings.TrimSpace(rule.Request.Body) != "" {
		bodyPattern, err := templateRegexp(rule.Request.Body, values, wildcards, false)
		if err != nil {
			unsupported = append(unsupported, "request body pattern unsupported: "+err.Error())
		} else {
			route.Body = bodyPattern
		}
	}
	for k, v := range rule.Request.Headers {
		headerPattern, err := templateRegexp(v, values, wildcards, false)
		if err != nil {
			unsupported = append(unsupported, "request header pattern unsupported: "+err.Error())
			continue
		}
		route.Headers[strings.ToLower(k)] = headerPattern
	}
	return route, unsupported
}

func responseForRule(rule *convert.XrayRule, opt Options, values map[string]string) (*ResponseSpec, []string) {
	resp := newResponseSpec()
	for k, v := range values {
		resp.Variables[k] = v
		switch k {
		case "randomstr":
			resp.Variables["randstr"] = v
		case "randomnum":
			resp.Variables["randnum"] = v
		}
	}
	expr := strings.TrimSpace(rule.Expression)
	if expr == "" {
		return resp, nil
	}
	ast, err := convert.ParseToAST(expr)
	if err != nil {
		return resp, []string{"parse expression: " + err.Error()}
	}
	hints := collectGroupHints(ast)
	var unsupported []string
	mutateForTruth(ast, resp, hints, opt, &unsupported)
	if ok, err := evalAST(ast, resp); err != nil {
		unsupported = append(unsupported, "evaluate generated response: "+err.Error())
	} else if !ok {
		unsupported = append(unsupported, "generated response does not satisfy expression")
	}
	return resp, unsupported
}

func applyExpressionVariableHints(expr string, values map[string]string) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return
	}
	ast, err := convert.ParseToAST(expr)
	if err != nil {
		return
	}
	var visit func(*dsl.Node)
	visit = func(node *dsl.Node) {
		if node == nil {
			return
		}
		if node.Type == dsl.NodeCall {
			switch node.FuncName {
			case "regex":
				if len(node.Children) == 2 {
					if pattern, ok := literalString(node.Children[0]); ok {
						if name, ok := outputVariableName(node.Children[1]); ok {
							if _, exists := values[name]; !exists {
								values[name] = regexSample(pattern, groupHints{})
							}
						}
					}
				}
			case "contains", "icontains":
				if len(node.Children) == 2 {
					if word, ok := literalString(node.Children[1]); ok {
						if name, ok := outputVariableName(node.Children[0]); ok {
							if _, exists := values[name]; !exists {
								values[name] = word
							}
						}
					}
				}
			}
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(ast)
}

func outputVariableName(node *dsl.Node) (string, bool) {
	if node == nil || node.Type != dsl.NodeVariable {
		return "", false
	}
	name := fmt.Sprint(node.Value)
	switch name {
	case "", "body", "title", "content_type", "all_headers", "header", "status_code", "duration", "latency", "response", "request", "matched":
		return "", false
	default:
		return name, true
	}
}

func mutateForTruth(node *dsl.Node, resp *ResponseSpec, hints groupHints, opt Options, unsupported *[]string) {
	if node == nil {
		return
	}
	switch node.Type {
	case dsl.NodeLiteral:
		if b, ok := node.Value.(bool); ok && !b {
			*unsupported = append(*unsupported, "literal false expression")
		}
	case dsl.NodeUnaryOp:
		// Negative predicates are intentionally left untouched; defaults often
		// satisfy !contains/!= without adding contradictory content.
		return
	case dsl.NodeBinaryOp:
		switch node.Op {
		case "&&":
			mutateForTruth(node.Children[0], resp, hints, opt, unsupported)
			mutateForTruth(node.Children[1], resp, hints, opt, unsupported)
		case "||":
			for _, child := range node.Children {
				candidate := resp.clone()
				localUnsupported := []string{}
				mutateForTruth(child, candidate, hints, opt, &localUnsupported)
				if ok, _ := evalAST(child, candidate); ok {
					*resp = *candidate
					return
				}
			}
			mutateForTruth(node.Children[0], resp, hints, opt, unsupported)
		default:
			mutateComparison(node, resp, hints, opt, unsupported)
		}
	case dsl.NodeCall:
		mutateCall(node, resp, hints, opt, unsupported)
	}
}

func mutateComparison(node *dsl.Node, resp *ResponseSpec, hints groupHints, opt Options, unsupported *[]string) {
	if len(node.Children) != 2 {
		return
	}
	left, right := node.Children[0], node.Children[1]
	if isStatusVar(left) {
		if n, ok := literalInt(right); ok {
			status, valid := chooseStatusCode(node.Op, n)
			if !valid {
				*unsupported = append(*unsupported, fmt.Sprintf("cannot generate valid HTTP status for response.status %s %d", node.Op, n))
				return
			}
			resp.StatusCode = status
			return
		}
	}
	if isContentLengthExpr(left) {
		if n, ok := literalInt(right); ok && node.Op == "==" {
			resp.setBodyLength(n)
			return
		}
	}
	if isDurationVar(left) || isLatencyVar(left) {
		if n, ok := literalFloat(right); ok {
			delay := chooseDelay(node.Op, n, isLatencyVar(left))
			if delay > opt.MaxDelay {
				*unsupported = append(*unsupported, fmt.Sprintf("required delay %s exceeds max %s", delay, opt.MaxDelay))
				return
			}
			resp.Delay = delay
			return
		}
	}
	if delay, ok := comparisonDelay(node, resp); ok {
		if delay > opt.MaxDelay {
			*unsupported = append(*unsupported, fmt.Sprintf("required delay %s exceeds max %s", delay, opt.MaxDelay))
			return
		}
		resp.Delay = delay
		return
	}
	if groupPattern, groupName, part, ok := regexGroupRef(left); ok {
		if value, ok := literalString(right); ok && (node.Op == "==" || node.Op == "!=") {
			if node.Op == "==" {
				hints[regexGroupKey(groupPattern, groupName)] = value
				addRegexSample(resp, groupPattern, part, hints)
			}
			return
		}
	}
	if groupPattern, groupName, part, ok := regexGroupRef(right); ok {
		if value, ok := literalString(left); ok && node.Op == "==" {
			hints[regexGroupKey(groupPattern, groupName)] = value
			addRegexSample(resp, groupPattern, part, hints)
			return
		}
	}
	if part := variablePart(left); part != "" {
		if value, ok := nodeStringValue(right, resp); ok && (node.Op == "==" || node.Op == "!=") {
			if node.Op == "==" {
				resp.addPart(part, value)
			} else if value == "" {
				resp.addPart(part, "harness")
			}
			return
		}
	}
}

func isContentLengthExpr(node *dsl.Node) bool {
	if node == nil {
		return false
	}
	if node.Type == dsl.NodeVariable && fmt.Sprint(node.Value) == "content_length" {
		return true
	}
	return node.Type == dsl.NodeCall && node.FuncName == "to_number" && len(node.Children) == 1 && isContentLengthExpr(node.Children[0])
}

func mutateCall(node *dsl.Node, resp *ResponseSpec, hints groupHints, opt Options, unsupported *[]string) {
	switch node.FuncName {
	case "contains", "icontains":
		if len(node.Children) != 2 {
			return
		}
		part := variablePart(node.Children[0])
		word, ok := nodeStringValue(node.Children[1], resp)
		if part != "" && ok {
			resp.addPart(part, word)
		}
	case "regex":
		if len(node.Children) != 2 {
			return
		}
		pattern, ok := nodeStringValue(node.Children[0], resp)
		part := variablePart(node.Children[1])
		if ok {
			if decodedPart := decodedVariablePart(node.Children[1], "base64_decode"); decodedPart != "" {
				resp.addBase64DecodedPart(decodedPart, regexSample(pattern, hints))
				return
			}
		}
		if ok && part != "" {
			addRegexSample(resp, pattern, part, hints)
		}
	case "starts_with":
		if len(node.Children) == 2 {
			if part := variablePart(node.Children[0]); part != "" {
				if value, ok := nodeStringValue(node.Children[1], resp); ok {
					resp.prependPart(part, value)
				}
			}
		}
	case "ends_with":
		if len(node.Children) == 2 {
			if part := variablePart(node.Children[0]); part != "" {
				if value, ok := nodeStringValue(node.Children[1], resp); ok {
					resp.addPart(part, value)
				}
			}
		}
	case "xray_regex_group":
		if pattern, _, part, ok := regexGroupRef(node); ok {
			addRegexSample(resp, pattern, part, hints)
		}
	case "xray_version_less", "xray_version_greater", "xray_version_equal", "xray_version_in":
		mutateVersionCall(node, resp, hints)
	case "xray_valid_page":
		resp.StatusCode = 200
		resp.addPart("body", "valid page")
	case "xray_gt", "xray_gte", "xray_lt", "xray_lte":
		if len(node.Children) == 2 {
			mutateComparison(dsl.BinaryOp(xrayCompareOp(node.FuncName), node.Children[0], node.Children[1]), resp, hints, opt, unsupported)
		}
	case "wait_for":
		return
	default:
		*unsupported = append(*unsupported, "unsupported predicate: "+node.FuncName)
	}
}

func decodedVariablePart(node *dsl.Node, fn string) string {
	if node == nil || node.Type != dsl.NodeCall || node.FuncName != fn || len(node.Children) != 1 {
		return ""
	}
	return variablePart(node.Children[0])
}

func xrayCompareOp(name string) string {
	switch name {
	case "xray_gt":
		return ">"
	case "xray_gte":
		return ">="
	case "xray_lt":
		return "<"
	case "xray_lte":
		return "<="
	default:
		return "=="
	}
}

func mutateVersionCall(node *dsl.Node, resp *ResponseSpec, hints groupHints) {
	if len(node.Children) != 2 {
		return
	}
	target, ok := literalString(node.Children[1])
	if !ok {
		return
	}
	value := versionWitness(node.FuncName, target)
	if value == "" {
		return
	}
	if pattern, group, part, ok := regexGroupRef(node.Children[0]); ok {
		hints[regexGroupKey(pattern, group)] = value
		addRegexSample(resp, pattern, part, hints)
		return
	}
	if part := variablePart(node.Children[0]); part != "" {
		resp.addPart(part, value)
	}
}

func collectGroupHints(node *dsl.Node) groupHints {
	hints := groupHints{}
	var visit func(*dsl.Node)
	visit = func(n *dsl.Node) {
		if n == nil {
			return
		}
		if n.Type == dsl.NodeCall && strings.HasPrefix(n.FuncName, "xray_version_") && len(n.Children) == 2 {
			if pattern, group, _, ok := regexGroupRef(n.Children[0]); ok {
				if target, ok := literalString(n.Children[1]); ok {
					if value := versionWitness(n.FuncName, target); value != "" {
						hints[regexGroupKey(pattern, group)] = value
					}
				}
			}
		}
		if n.Type == dsl.NodeBinaryOp && len(n.Children) == 2 && n.Op == "==" {
			if pattern, group, _, ok := regexGroupRef(n.Children[0]); ok {
				if value, ok := literalString(n.Children[1]); ok {
					hints[regexGroupKey(pattern, group)] = value
				}
			}
			if pattern, group, _, ok := regexGroupRef(n.Children[1]); ok {
				if value, ok := literalString(n.Children[0]); ok {
					hints[regexGroupKey(pattern, group)] = value
				}
			}
		}
		for _, child := range n.Children {
			visit(child)
		}
	}
	visit(node)
	return hints
}

func versionWitness(fn, target string) string {
	target = strings.TrimSpace(target)
	switch fn {
	case "xray_version_equal":
		return strings.TrimLeft(strings.TrimPrefix(target, "="), " ")
	case "xray_version_greater":
		return bumpVersion(strings.TrimLeft(strings.TrimPrefix(target, ">"), " "))
	case "xray_version_less":
		return lowerVersion(strings.TrimLeft(strings.TrimPrefix(target, "<"), " "))
	case "xray_version_in":
		if strings.Contains(target, ">") && strings.Contains(target, "<") {
			parts := strings.Split(target, ",")
			base := "1.0.0"
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, ">=") {
					base = strings.TrimSpace(strings.TrimPrefix(part, ">="))
				} else if strings.HasPrefix(part, ">") {
					base = bumpVersion(strings.TrimSpace(strings.TrimPrefix(part, ">")))
				}
			}
			return base
		}
		if strings.Contains(target, "<") {
			return lowerVersion(strings.TrimLeft(strings.TrimLeft(target, "<="), " "))
		}
		if strings.Contains(target, ">") {
			return bumpVersion(strings.TrimLeft(strings.TrimLeft(target, ">="), " "))
		}
		if strings.Contains(target, "=") {
			return strings.TrimLeft(strings.TrimPrefix(target, "="), " ")
		}
		return target
	default:
		return ""
	}
}

func bumpVersion(v string) string {
	nums := versionNums(v)
	if len(nums) == 0 {
		return "9999.0.0"
	}
	nums[len(nums)-1]++
	return joinVersion(nums)
}

func lowerVersion(v string) string {
	nums := versionNums(v)
	if len(nums) == 0 {
		return "0.0.1"
	}
	for i := len(nums) - 1; i >= 0; i-- {
		if nums[i] > 0 {
			nums[i]--
			return joinVersion(nums)
		}
	}
	return "0.0.0"
}

func versionNums(v string) []int {
	fields := regexp.MustCompile(`\d+`).FindAllString(v, -1)
	nums := make([]int, 0, len(fields))
	for _, field := range fields {
		n, _ := strconv.Atoi(field)
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums
}

func joinVersion(nums []int) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

func addRegexSample(resp *ResponseSpec, pattern, part string, hints groupHints) {
	if (part == "header" || part == "all_headers") && strings.Contains(strings.ToLower(pattern), "location") && strings.Contains(pattern, "example.com") {
		resp.Headers["Location"] = "//example.com"
		return
	}
	if part == "body" || part == "" {
		switch {
		case strings.Contains(pattern, "username") && strings.Contains(pattern, "allowed_web_site"):
			resp.addPart("body", `{"username": "admin", "phone_number": "1", "allowed_web_site": ""}`)
			return
		case strings.Contains(pattern, "result") && strings.Contains(pattern, "true"):
			resp.addPart("body", `{"result":true}`)
			return
		}
	}
	sample := regexSample(pattern, hints)
	if sample == "" {
		sample = "x"
	}
	resp.addPart(part, sample)
}

func (r *ResponseSpec) clone() *ResponseSpec {
	cp := &ResponseSpec{StatusCode: r.StatusCode, Body: r.Body, Delay: r.Delay, Headers: map[string]string{}, Variables: map[string]string{}}
	for k, v := range r.Headers {
		cp.Headers[k] = v
	}
	for k, v := range r.Variables {
		cp.Variables[k] = v
	}
	return cp
}

func (r *ResponseSpec) addPart(part, value string) {
	if value == "" {
		return
	}
	switch part {
	case "body", "":
		if !strings.Contains(r.Body, value) {
			if r.Body == "" {
				r.Body = value
			} else {
				r.Body += "\n" + value
			}
		}
	case "title":
		if !strings.Contains(r.Body, "<title>") {
			r.Body += "\n<html><head><title>" + html.EscapeString(value) + "</title></head></html>"
		} else if !strings.Contains(r.Body, value) {
			r.Body += value
		}
	case "content_type":
		r.Headers["Content-Type"] = value
	case "header", "all_headers":
		name, headerValue := headerFromContains(value)
		if existing := r.Headers[name]; existing == "1" {
			r.Headers[name] = headerValue
		} else if existing != "" && !strings.Contains(existing, headerValue) {
			r.Headers[name] = existing + " " + headerValue
		} else if existing == "" {
			r.Headers[name] = headerValue
		}
	default:
		if isHeaderPart(part) {
			name := canonicalHeaderName(part)
			if existing := r.Headers[name]; existing == "1" {
				r.Headers[name] = value
			} else if existing != "" && !strings.Contains(existing, value) {
				r.Headers[name] = existing + " " + value
			} else if existing == "" {
				r.Headers[name] = value
			}
		}
	}
}

func (r *ResponseSpec) prependPart(part, value string) {
	if part == "body" || part == "" {
		r.Body = value + r.Body
		return
	}
	r.addPart(part, value)
}

func (r *ResponseSpec) addBase64DecodedPart(part, value string) {
	if part != "body" && part != "" {
		r.addPart(part, value)
		return
	}
	decoded := ""
	if r.Body != "" {
		if data, err := base64.StdEncoding.DecodeString(r.Body); err == nil {
			decoded = string(data)
		}
	}
	if !strings.Contains(decoded, value) {
		decoded += value
	}
	r.Body = base64.StdEncoding.EncodeToString([]byte(decoded))
}

func (r *ResponseSpec) setBodyLength(n int) {
	if n < 0 {
		return
	}
	if len(r.Body) > n {
		r.Body = r.Body[:n]
		return
	}
	if len(r.Body) < n {
		if r.Body == "" && n > 0 {
			r.Body = "1"
		}
		r.Body += strings.Repeat("A", n-len(r.Body))
	}
}

func (r *ResponseSpec) event() map[string]interface{} {
	data := map[string]interface{}{
		"status_code": r.StatusCode,
		"duration":    r.Delay.Seconds(),
		"latency":     float64(r.Delay.Milliseconds()),
		"body":        r.Body,
		"title":       extractTitle(r.Body),
	}
	for k, v := range r.Variables {
		data[k] = numericOrString(v)
	}
	var all strings.Builder
	var raw strings.Builder
	keys := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.Headers[k]
		raw.WriteString(k + ": " + v + "\r\n")
		normalized := headerVarName(k)
		data[normalized] = v
		all.WriteString(normalized + ": " + v + "\r\n")
	}
	data["header"] = raw.String()
	data["all_headers"] = all.String()
	data["content_length"] = len(r.Body)
	if ct := r.Headers["Content-Type"]; ct != "" {
		data["content_type"] = ct
	}
	return data
}

func numericOrString(value string) interface{} {
	if value == "" {
		return value
	}
	if strings.ContainsAny(value, ".") {
		if n, err := strconv.ParseFloat(value, 64); err == nil {
			return n
		}
		return value
	}
	if n, err := strconv.Atoi(value); err == nil {
		return n
	}
	return value
}

func evalAST(ast *dsl.Node, resp *ResponseSpec) (bool, error) {
	expr := neutralizeWaitForDSL(ast.String())
	if strings.Contains(expr, "{{") {
		rendered, err := common.Evaluate(expr, resp.event())
		if err == nil {
			expr = rendered
		}
	}
	value, err := common.Eval(expr, resp.event())
	if err != nil {
		return false, err
	}
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		return v != "", nil
	default:
		return fmt.Sprint(v) != "" && fmt.Sprint(v) != "0", nil
	}
}

func applyOutputs(outputs map[string]interface{}, resp *ResponseSpec, values map[string]string) []string {
	if len(outputs) == 0 {
		return nil
	}
	sources := map[string]submatchSpec{}
	for name, raw := range outputs {
		if spec, ok := parseSubmatch(fmt.Sprint(raw)); ok {
			sources[name] = spec
		}
	}
	referencedSources := referencedOutputSources(outputs)

	var unsupported []string
	for name, raw := range outputs {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if spec, ok := parseSubmatch(expr); ok {
			if referencedSources[name] {
				continue
			}
			value := ensureOutputValue(spec, resp)
			if spec.GroupName != "" {
				values[name] = value
			}
			continue
		}
		if assigned, ok := transformedOutputValue(name, expr, sources, resp, values); ok {
			values[name] = assigned
			resp.Variables[name] = assigned
			continue
		}
		if assigned, ok := simpleOutputValue(expr, resp); ok {
			values[name] = assigned
			resp.Variables[name] = assigned
			continue
		}
		if source, group, ok := outputSource(expr); ok {
			spec, exists := sources[source]
			if !exists {
				unsupported = append(unsupported, "unresolved output source: "+source)
				continue
			}
			spec.GroupName = group
			values[name] = ensureOutputValue(spec, resp)
			continue
		}
		if lit, ok := literalOutput(expr); ok {
			values[name] = lit
			resp.Variables[name] = lit
		}
	}
	return unsupported
}

func referencedOutputSources(outputs map[string]interface{}) map[string]bool {
	refs := map[string]bool{}
	for _, raw := range outputs {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if source, _, _, _, ok := parseReplaceAllOutput(expr); ok {
			refs[source] = true
			continue
		}
		if source, _, _, ok := parseUnaryOutputTransform(expr); ok {
			refs[source] = true
			continue
		}
		if source, _, ok := outputSource(expr); ok {
			refs[source] = true
		}
	}
	return refs
}

func transformedOutputValue(name, expr string, sources map[string]submatchSpec, resp *ResponseSpec, values map[string]string) (string, bool) {
	if source, group, old, newValue, ok := parseReplaceAllOutput(expr); ok {
		spec, exists := sources[source]
		if !exists {
			return "", false
		}
		spec.GroupName = group
		value := ensureOutputValue(spec, resp)
		return strings.ReplaceAll(value, old, newValue), true
	}
	if source, group, fn, ok := parseUnaryOutputTransform(expr); ok {
		spec, exists := sources[source]
		if !exists {
			return "", false
		}
		spec.GroupName = group
		switch fn {
		case "base64Decode":
			if expected := values[name]; expected != "" {
				encoded := base64.StdEncoding.EncodeToString([]byte(expected))
				ensureOutputValueWithHint(spec, resp, encoded)
				return expected, true
			}
			value := ensureOutputValue(spec, resp)
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return "", false
			}
			return string(decoded), true
		case "hexDecode":
			if expected := values[name]; expected != "" {
				encoded := hex.EncodeToString([]byte(expected))
				ensureOutputValueWithHint(spec, resp, encoded)
				return expected, true
			}
			value := ensureOutputValue(spec, resp)
			decoded, err := hex.DecodeString(value)
			if err != nil {
				return "", false
			}
			return string(decoded), true
		case "urlencode", "urlEncode", "url_encode":
			value := ensureOutputValue(spec, resp)
			return url.QueryEscape(value), true
		default:
			return "", false
		}
	}
	return "", false
}

type submatchSpec struct {
	Pattern   string
	Part      string
	GroupName string
}

func parseSubmatch(expr string) (submatchSpec, bool) {
	if spec, ok := parseConcatSubmatch(expr); ok {
		return spec, true
	}
	pattern, rest, ok := leadingString(expr)
	if !ok {
		return submatchSpec{}, false
	}
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, ".submatch(") && !strings.HasPrefix(rest, ".bsubmatch(") {
		return submatchSpec{}, false
	}
	start := strings.IndexByte(rest, '(')
	end := matchingParen(rest, start)
	if end < 0 {
		return submatchSpec{}, false
	}
	part := responsePart(strings.TrimSpace(rest[start+1 : end]))
	group := ""
	tail := strings.TrimSpace(rest[end+1:])
	if strings.HasPrefix(tail, "[") {
		if g, _, ok := leadingString(tail[1:]); ok {
			group = g
		} else {
			close := strings.IndexByte(tail, ']')
			if close > 1 {
				group = strings.TrimSpace(tail[1:close])
			}
		}
	}
	return submatchSpec{Pattern: pattern, Part: part, GroupName: group}, true
}

func parseConcatSubmatch(expr string) (submatchSpec, bool) {
	re := regexp.MustCompile(`\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*string\((?:"([^"]*)"|'([^']*)')\)\s*\)\.(?:submatch|bsubmatch)\(([^)]*)\)`)
	match := re.FindStringSubmatch(expr)
	if len(match) == 0 {
		return submatchSpec{}, false
	}
	pattern := match[1]
	if pattern == "" {
		pattern = match[2]
	}
	return submatchSpec{Pattern: pattern, Part: responsePart(match[3])}, true
}

func ensureOutputValue(spec submatchSpec, resp *ResponseSpec) string {
	return ensureOutputValueWithHint(spec, resp, "")
}

func ensureOutputValueWithHint(spec submatchSpec, resp *ResponseSpec, groupValue string) string {
	hints := groupHints{}
	if spec.GroupName != "" && groupValue != "" {
		hints[regexGroupKey(spec.Pattern, spec.GroupName)] = groupValue
	}
	sample := regexSample(spec.Pattern, hints)
	resp.addPart(spec.Part, sample)
	if spec.GroupName == "" {
		return sample
	}
	return regexGroupValue(spec.Pattern, sample, spec.GroupName)
}

func outputSource(expr string) (string, string, bool) {
	expr = strings.TrimSpace(expr)
	open := strings.IndexByte(expr, '[')
	close := strings.LastIndexByte(expr, ']')
	if open <= 0 || close <= open {
		return "", "", false
	}
	source := strings.TrimSpace(expr[:open])
	group, _, ok := leadingString(expr[open+1 : close])
	if !ok {
		group = strings.TrimSpace(expr[open+1 : close])
	}
	return source, group, source != "" && group != ""
}

func parseReplaceAllOutput(expr string) (string, string, string, string, bool) {
	args, ok := parseCallArgs(expr, "replaceAll")
	if !ok || len(args) != 3 {
		return "", "", "", "", false
	}
	source, group, ok := parseSourceArg(args[0])
	if !ok {
		return "", "", "", "", false
	}
	oldValue, ok := literalOutput(args[1])
	if !ok {
		return "", "", "", "", false
	}
	newValue, ok := literalOutput(args[2])
	if !ok {
		return "", "", "", "", false
	}
	return source, group, oldValue, newValue, true
}

func parseUnaryOutputTransform(expr string) (string, string, string, bool) {
	for _, fn := range []string{"base64Decode", "hexDecode", "urlencode", "urlEncode", "url_encode"} {
		args, ok := parseCallArgs(expr, fn)
		if !ok || len(args) != 1 {
			continue
		}
		source, group, ok := parseSourceArg(args[0])
		if !ok {
			continue
		}
		return source, group, fn, true
	}
	return "", "", "", false
}

func parseSourceArg(expr string) (string, string, bool) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "string(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[len("string(") : len(expr)-1])
	}
	return outputSource(expr)
}

func parseCallArgs(expr, name string) ([]string, bool) {
	expr = strings.TrimSpace(expr)
	prefix := name + "("
	if !strings.HasPrefix(expr, prefix) || !strings.HasSuffix(expr, ")") {
		return nil, false
	}
	inner := strings.TrimSpace(expr[len(prefix) : len(expr)-1])
	if inner == "" {
		return nil, true
	}
	return splitArgs(inner), true
}

func splitArgs(expr string) []string {
	var parts []string
	depth := 0
	start := 0
	quote := byte(0)
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(expr) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(expr[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(expr[start:]))
	return parts
}

func literalOutput(expr string) (string, bool) {
	value, rest, ok := leadingString(expr)
	return value, ok && strings.TrimSpace(rest) == ""
}

func simpleOutputValue(expr string, resp *ResponseSpec) (string, bool) {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "response.latency":
		return strconv.FormatInt(resp.Delay.Milliseconds(), 10), true
	case "response.status":
		return strconv.Itoa(resp.StatusCode), true
	case "response.body", "response.body_string":
		return resp.Body, true
	case "response.content_type":
		return resp.Headers["Content-Type"], true
	}
	if strings.HasPrefix(expr, "response.headers[") {
		re := regexp.MustCompile(`response\.headers\[['"]([^'"]+)['"]\]`)
		if match := re.FindStringSubmatch(expr); len(match) > 1 {
			return resp.Headers[canonicalHeaderName(match[1])], true
		}
	}
	value, err := common.Eval(expr, resp.event())
	if err != nil {
		return "", false
	}
	return fmt.Sprint(value), true
}

func leadingString(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == 'r' || s[0] == 'b') && (s[1] == '\'' || s[1] == '"') {
		raw := s[0] == 'r'
		value, end, ok := scanQuoted(s, 1, raw)
		return value, s[end:], ok
	}
	if len(s) == 0 || (s[0] != '\'' && s[0] != '"') {
		return "", "", false
	}
	value, end, ok := scanQuoted(s, 0, false)
	return value, s[end:], ok
}

func scanQuoted(s string, start int, raw bool) (string, int, bool) {
	quote := s[start]
	var b strings.Builder
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if raw {
				b.WriteByte(s[i])
			}
			i++
			b.WriteByte(s[i])
			continue
		}
		if s[i] == quote {
			return b.String(), i + 1, true
		}
		b.WriteByte(s[i])
	}
	return "", 0, false
}

func matchingParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' {
			_, end, ok := scanQuoted(s, i, false)
			if ok {
				i = end - 1
				continue
			}
		}
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func responsePart(expr string) string {
	switch {
	case strings.Contains(expr, "response.body"):
		return "body"
	case strings.Contains(expr, "response.title"):
		return "body"
	case strings.Contains(expr, "response.content_type"):
		return "content_type"
	case strings.Contains(expr, "response.raw_header"):
		return "header"
	case strings.Contains(expr, "response.headers"):
		re := regexp.MustCompile(`response\.headers\[['"]([^'"]+)['"]\]`)
		if match := re.FindStringSubmatch(expr); len(match) > 1 {
			return headerVarName(match[1])
		}
		return "header"
	default:
		return "body"
	}
}

func variablePart(node *dsl.Node) string {
	if node == nil || node.Type != dsl.NodeVariable {
		return ""
	}
	name := fmt.Sprint(node.Value)
	switch name {
	case "body", "title", "content_type", "all_headers", "header":
		return name
	case "response", "request", "matched":
		return ""
	default:
		if isHeaderPart(name) {
			return name
		}
		return ""
	}
}

func regexGroupRef(node *dsl.Node) (string, string, string, bool) {
	if node == nil || node.Type != dsl.NodeCall || node.FuncName != "xray_regex_group" || len(node.Children) != 3 {
		return "", "", "", false
	}
	pattern, ok := literalString(node.Children[0])
	if !ok {
		return "", "", "", false
	}
	part := variablePart(node.Children[1])
	if part == "" {
		part = "body"
	}
	group, ok := literalString(node.Children[2])
	if !ok {
		group = fmt.Sprint(node.Children[2].Value)
	}
	return pattern, group, part, true
}

func isStatusVar(node *dsl.Node) bool {
	return node != nil && node.Type == dsl.NodeVariable && fmt.Sprint(node.Value) == "status_code"
}

func isDurationVar(node *dsl.Node) bool {
	return node != nil && node.Type == dsl.NodeVariable && fmt.Sprint(node.Value) == "duration"
}

func isLatencyVar(node *dsl.Node) bool {
	return node != nil && node.Type == dsl.NodeVariable && fmt.Sprint(node.Value) == "latency"
}

func literalString(node *dsl.Node) (string, bool) {
	if node == nil || node.Type != dsl.NodeLiteral {
		return "", false
	}
	switch v := node.Value.(type) {
	case string:
		return v, true
	case int:
		return strconv.Itoa(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	default:
		return fmt.Sprint(v), true
	}
}

func nodeStringValue(node *dsl.Node, resp *ResponseSpec) (string, bool) {
	if value, ok := literalString(node); ok {
		return renderResponseString(value, resp), true
	}
	value, err := common.Eval(node.String(), resp.event())
	if err != nil {
		return "", false
	}
	return fmt.Sprint(value), true
}

func renderResponseString(value string, resp *ResponseSpec) string {
	if !strings.Contains(value, "{{") {
		return value
	}
	rendered, err := common.Evaluate(value, resp.event())
	if err != nil {
		return value
	}
	return rendered
}

func literalInt(node *dsl.Node) (int, bool) {
	if node == nil || node.Type != dsl.NodeLiteral {
		return 0, false
	}
	switch v := node.Value.(type) {
	case int:
		return v, true
	case float64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	default:
		return 0, false
	}
}

func literalFloat(node *dsl.Node) (float64, bool) {
	if node == nil || node.Type != dsl.NodeLiteral {
		return 0, false
	}
	switch v := node.Value.(type) {
	case int:
		return float64(v), true
	case float64:
		return v, true
	case string:
		n, err := strconv.ParseFloat(v, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func chooseNumber(op string, target int) int {
	switch op {
	case "==":
		return target
	case "!=":
		if target == 200 {
			return 201
		}
		return 200
	case ">":
		return target + 1
	case ">=":
		return target
	case "<":
		if target > 0 {
			return target - 1
		}
		return target
	case "<=":
		return target
	default:
		return 200
	}
}

func chooseStatusCode(op string, target int) (int, bool) {
	const (
		minStatus = 100
		maxStatus = 599
	)

	switch op {
	case "==":
		if target < minStatus || target > maxStatus {
			return 0, false
		}
		return target, true
	case "!=":
		if target != http.StatusOK {
			return http.StatusOK, true
		}
		return http.StatusCreated, true
	case ">":
		status := target + 1
		if status < minStatus {
			status = minStatus
		}
		if status > maxStatus {
			return 0, false
		}
		return status, true
	case ">=":
		status := target
		if status < minStatus {
			status = minStatus
		}
		if status > maxStatus {
			return 0, false
		}
		return status, true
	case "<":
		status := target - 1
		if status > maxStatus {
			status = maxStatus
		}
		if status < minStatus {
			return 0, false
		}
		return status, true
	case "<=":
		status := target
		if status > maxStatus {
			status = maxStatus
		}
		if status < minStatus {
			return 0, false
		}
		return status, true
	default:
		return 0, false
	}
}

func chooseDelay(op string, target float64, millis bool) time.Duration {
	unit := time.Second
	if millis {
		unit = time.Millisecond
	}
	switch op {
	case ">":
		return time.Duration(target+1) * unit
	case ">=":
		delay := time.Duration(target) * unit
		if millis {
			delay += latencyLowerBoundMargin
		}
		return delay
	default:
		return 0
	}
}

func comparisonDelay(node *dsl.Node, resp *ResponseSpec) (time.Duration, bool) {
	if node == nil || node.Type != dsl.NodeBinaryOp || len(node.Children) != 2 {
		return 0, false
	}
	if node.Op != ">" && node.Op != ">=" {
		return 0, false
	}
	left := node.Children[0]
	if left.Type != dsl.NodeCall || left.FuncName != "xray_sub" || len(left.Children) != 2 || !isLatencyVar(left.Children[0]) {
		return 0, false
	}
	offsetRaw, err := common.Eval(left.Children[1].String(), resp.event())
	if err != nil {
		return 0, false
	}
	targetRaw, err := common.Eval(node.Children[1].String(), resp.event())
	if err != nil {
		return 0, false
	}
	offset, ok1 := parseFloat(offsetRaw)
	target, ok2 := parseFloat(targetRaw)
	if !ok1 || !ok2 {
		return 0, false
	}
	if node.Op == ">" {
		target++
	}
	return time.Duration(offset+target)*time.Millisecond + latencyLowerBoundMargin, true
}

func parseFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	case string:
		n, err := strconv.ParseFloat(v, 64)
		return n, err == nil
	default:
		n, err := strconv.ParseFloat(fmt.Sprint(v), 64)
		return n, err == nil
	}
}

func templateRegexp(tmpl string, values map[string]string, wildcards map[string]bool, forPath bool) (*Pattern, error) {
	var b strings.Builder
	b.WriteString("^")
	last := 0
	matches := placeholderRE.FindAllStringSubmatchIndex(tmpl, -1)
	groups := map[string]string{}
	groupIndex := 0
	for _, match := range matches {
		lit := tmpl[last:match[0]]
		b.WriteString(regexp.QuoteMeta(lit))
		name := strings.TrimSpace(tmpl[match[2]:match[3]])
		if value, ok := values[name]; ok && !wildcards[name] {
			if forPath && strings.HasSuffix(lit, "/") {
				value = strings.TrimLeft(value, "/")
			}
			b.WriteString(regexp.QuoteMeta(value))
		} else if forPath {
			groupIndex++
			group := captureName(name, groupIndex)
			groups[group] = name
			b.WriteString(`(?P<` + group + `>[^?#]*)`)
		} else {
			groupIndex++
			group := captureName(name, groupIndex)
			groups[group] = name
			b.WriteString(`(?P<` + group + `>[\s\S]*?)`)
		}
		last = match[1]
	}
	b.WriteString(regexp.QuoteMeta(tmpl[last:]))
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	return &Pattern{Re: re, Groups: groups}, nil
}

func captureName(name string, index int) string {
	var b strings.Builder
	b.WriteString("h")
	b.WriteString(strconv.Itoa(index))
	b.WriteString("_")
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() <= 4 {
		b.WriteString("var")
	}
	return b.String()
}

func initialValues(poc *convert.XrayPOC) (map[string]string, map[string]bool) {
	values := map[string]string{}
	wildcards := map[string]bool{}
	for k, raw := range poc.Set {
		s := strings.TrimSpace(fmt.Sprint(raw))
		if s == "" {
			continue
		}
		if isHarnessRootURLExpression(s) {
			wildcards[k] = true
			continue
		}
		if isHarnessURLValue(s) {
			wildcards[k] = true
			continue
		}
		if strings.Contains(s, "(") && !isQuoted(s) {
			values[k] = syntheticSetValue(s)
			wildcards[k] = true
			continue
		}
		if v, ok := literalOutput(s); ok {
			values[k] = v
		} else {
			values[k] = s
		}
	}
	return values, wildcards
}

func setExpressions(poc *convert.XrayPOC) map[string]string {
	exprs := map[string]string{}
	for k, raw := range poc.Set {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if expr != "" {
			exprs[k] = expr
		}
	}
	return exprs
}

func deriveSetVariables(exprs map[string]string, values map[string]string) {
	for i := 0; i < len(exprs)+2; i++ {
		changed := false
		for key, expr := range exprs {
			before := cloneStringMap(values)
			if value, ok := reverseSetExpression(key, expr, values); ok {
				if values[key] != value {
					values[key] = value
					changed = true
				}
				if !sameStringMap(before, values) {
					changed = true
				}
				continue
			}
			if value, ok := evalSetExpression(expr, values); ok && values[key] != value {
				values[key] = value
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for k, v := range left {
		if right[k] != v {
			return false
		}
	}
	return true
}

func evalSetExpression(expr string, values map[string]string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || hasNonDeterministicSetCall(expr) {
		return "", false
	}
	ast, err := convert.ParseToAST(expr)
	if err != nil {
		return "", false
	}
	data := map[string]interface{}{}
	for k, v := range values {
		data[k] = v
	}
	result, err := common.Eval(ast.String(), data)
	if err != nil {
		return "", false
	}
	return fmt.Sprint(result), true
}

func hasNonDeterministicSetCall(expr string) bool {
	expr = strings.TrimSpace(expr)
	lower := strings.ToLower(expr)
	return strings.Contains(lower, "random") || strings.Contains(lower, "rand_") || strings.Contains(lower, "get404path(")
}

func reverseSetExpression(key, expr string, values map[string]string) (string, bool) {
	captured := values[key]
	if captured == "" {
		return "", false
	}
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "hex(") && strings.HasSuffix(expr, ")") {
		dep := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "hex("), ")"))
		decoded, err := hex.DecodeString(captured)
		if err == nil && dep != "" {
			values[dep] = string(decoded)
			return captured, true
		}
	}
	if inner, ok := unwrapAnyFunc(expr, "urlencode", "urlEncode", "urlencodeall", "urlEncodeAll", "url_encode"); ok {
		decoded, err := url.QueryUnescape(captured)
		if err != nil {
			return "", false
		}
		if inferDerivedExpressionValues(inner, decoded, values) {
			return captured, true
		}
		return "", false
	}
	if inner, ok := unwrapFunc(expr, "base64"); ok {
		decoded, err := base64.StdEncoding.DecodeString(captured)
		if err != nil {
			return "", false
		}
		if inferDerivedExpressionValues(inner, string(decoded), values) {
			return captured, true
		}
		return "", false
	}
	if inner, ok := unwrapAnyWholeFunc(expr, "bytes", "string"); ok {
		if captured == syntheticSetValue(expr) {
			return "", false
		}
		if inferDerivedExpressionValues(inner, captured, values) {
			return captured, true
		}
		return "", false
	}
	if base, ok := parseBFormat16Expression(expr); ok {
		decoded, err := hex.DecodeString(captured)
		if err != nil {
			return "", false
		}
		values[base] = string(decoded)
		return captured, true
	}
	if strings.Contains(expr, "+") || strings.Contains(expr, "string(") {
		if inferConcatExpressionValues(expr, captured, values) {
			return captured, true
		}
		return "", false
	}
	return "", false
}

func inferDerivedExpressionValues(expr, actual string, values map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if dep, ok := unwrapAnyFunc(expr, "base64"); ok {
		decoded, err := base64.StdEncoding.DecodeString(actual)
		if err != nil {
			return false
		}
		return inferDerivedExpressionValues(dep, string(decoded), values)
	}
	if dep, ok := unwrapAnyFunc(expr, "urlencode", "urlEncode", "urlencodeall", "urlEncodeAll", "url_encode"); ok {
		decoded, err := url.QueryUnescape(actual)
		if err != nil {
			return false
		}
		return inferDerivedExpressionValues(dep, decoded, values)
	}
	return inferConcatExpressionValues(expr, actual, values)
}

func parseBFormat16Expression(expr string) (string, bool) {
	re := regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\.bformat\(\s*16\s*,\s*0\s*,\s*(?:""|'')\s*,\s*0\s*\)\s*$`)
	match := re.FindStringSubmatch(expr)
	if len(match) != 2 {
		return "", false
	}
	return match[1], true
}

func unwrapFunc(expr, name string) (string, bool) {
	prefix := name + "("
	expr = strings.TrimSpace(expr)
	if !strings.HasPrefix(expr, prefix) || !strings.HasSuffix(expr, ")") {
		return "", false
	}
	return strings.TrimSpace(expr[len(prefix) : len(expr)-1]), true
}

func unwrapAnyFunc(expr string, names ...string) (string, bool) {
	for _, name := range names {
		if inner, ok := unwrapFunc(expr, name); ok {
			return inner, true
		}
	}
	return "", false
}

func unwrapAnyWholeFunc(expr string, names ...string) (string, bool) {
	for _, name := range names {
		if inner, ok := unwrapWholeFunc(expr, name); ok {
			return inner, true
		}
	}
	return "", false
}

func unwrapWholeFunc(expr, name string) (string, bool) {
	expr = strings.TrimSpace(expr)
	prefix := name + "("
	if !strings.HasPrefix(expr, prefix) {
		return "", false
	}
	depth := 0
	quote := rune(0)
	escaped := false
	open := len(name)
	for idx, r := range expr[open:] {
		pos := open + idx
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if pos != len(expr)-1 {
					return "", false
				}
				return strings.TrimSpace(expr[open+1 : pos]), true
			}
		}
	}
	return "", false
}

func inferConcatExpressionValues(expr, actual string, values map[string]string) bool {
	parts := splitConcatExpr(expr)
	var b strings.Builder
	groupVars := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if len(parts) == 1 {
			if _, ok := values[part]; ok {
				values[part] = actual
				return true
			}
		}
		if strings.HasPrefix(part, "string(") && strings.HasSuffix(part, ")") {
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(part, "string("), ")"))
			if lit, ok := literalOutput(inner); ok {
				b.WriteString(regexp.QuoteMeta(lit))
				continue
			}
			groupVars = append(groupVars, inner)
			b.WriteString(`(?P<` + captureName(inner, len(groupVars)) + `>.*?)`)
			continue
		}
		if _, ok := values[part]; ok {
			groupVars = append(groupVars, part)
			b.WriteString(`(?P<` + captureName(part, len(groupVars)) + `>.*?)`)
			continue
		}
		if lit, ok := literalOutput(part); ok {
			b.WriteString(regexp.QuoteMeta(lit))
		}
	}
	if len(groupVars) == 0 {
		return false
	}
	re, err := regexp.Compile("^" + b.String() + "$")
	if err != nil {
		return false
	}
	matches := re.FindStringSubmatch(actual)
	if len(matches) == 0 {
		return false
	}
	names := re.SubexpNames()
	changed := false
	for i, name := range names {
		if i == 0 || name == "" {
			continue
		}
		for _, variable := range groupVars {
			if strings.HasSuffix(name, "_"+variable) {
				if values[variable] != matches[i] {
					values[variable] = matches[i]
					changed = true
				}
				break
			}
		}
	}
	return changed || len(matches) > 0
}

func splitConcatExpr(expr string) []string {
	var parts []string
	depth := 0
	start := 0
	quote := byte(0)
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(expr) {
				i++
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '+':
			if depth == 0 {
				parts = append(parts, expr[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, expr[start:])
	return parts
}

func isHarnessRootURLExpression(expr string) bool {
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

func isHarnessURLValue(expr string) bool {
	compact := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(expr), " ", ""), "'", `"`)
	switch compact {
	case "request.url", "response.url", "request.url.url", "response.url.url":
		return true
	default:
		return false
	}
}

func syntheticSetValue(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "randomInt(") {
		inside := strings.TrimSuffix(strings.TrimPrefix(expr, "randomInt("), ")")
		parts := strings.Split(inside, ",")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
		if len(parts) == 1 {
			return strings.TrimSpace(parts[0])
		}
		return "1"
	}
	if strings.HasPrefix(expr, "randomLowercase(") {
		return "harness"
	}
	if strings.HasPrefix(expr, "random") || strings.HasPrefix(expr, "get404Path(") {
		return "harness"
	}
	return "harness"
}

func selectPayloadRow(poc *convert.XrayPOC) map[string]string {
	rows := payloadRows(poc.Payloads)
	for _, row := range rows {
		for _, value := range row {
			if value != "" {
				return row
			}
		}
	}
	if len(rows) > 0 {
		return rows[0]
	}
	return nil
}

func payloadRows(root convert.XrayPayloadRoot) []map[string]string {
	keys := make([]string, 0, len(root.Payloads))
	for k := range root.Payloads {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return payloadRowNum(keys[i]) < payloadRowNum(keys[j])
	})
	var rows []map[string]string
	for _, key := range keys {
		row := map[string]string{}
		for name, raw := range root.Payloads[key] {
			value := strings.TrimSpace(fmt.Sprint(raw))
			if lit, ok := literalOutput(value); ok {
				value = lit
			}
			row[name] = value
		}
		rows = append(rows, row)
	}
	return rows
}

func payloadRowNum(s string) int {
	s = strings.TrimLeft(strings.ToLower(s), "p")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 1 << 30
	}
	return n
}

func scenarioRuleSets(poc *convert.XrayPOC) [][]string {
	top := convert.ParseTopExpression(poc.Expression)
	if top == nil {
		return [][]string{sortedRuleKeys(poc.Rules)}
	}
	sets := dnfRuleSets(top, poc.Rules)
	if len(sets) == 0 {
		return [][]string{orderedExistingRules(top, poc.Rules)}
	}
	return sets
}

func dnfRuleSets(node *convert.TopExprNode, rules map[string]convert.XrayRule) [][]string {
	if node == nil {
		return nil
	}
	switch node.Type {
	case "call":
		if _, ok := rules[node.Name]; ok {
			return [][]string{{node.Name}}
		}
		return nil
	case "literal":
		if node.Value {
			return [][]string{{}}
		}
		return nil
	case "or":
		var out [][]string
		for _, child := range node.Children {
			out = append(out, dnfRuleSets(child, rules)...)
		}
		return dedupeRuleSets(out)
	case "and":
		out := [][]string{{}}
		for _, child := range node.Children {
			childSets := dnfRuleSets(child, rules)
			if len(childSets) == 0 {
				continue
			}
			var next [][]string
			for _, left := range out {
				for _, right := range childSets {
					next = append(next, appendRuleNames(left, right))
				}
			}
			out = next
		}
		return dedupeRuleSets(out)
	default:
		return nil
	}
}

func orderedExistingRules(top *convert.TopExprNode, rules map[string]convert.XrayRule) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range convert.CollectRuleNames(top) {
		if seen[name] {
			continue
		}
		if _, ok := rules[name]; ok {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func hasTopLevelUnsupported(poc *convert.XrayPOC) bool {
	expr := strings.TrimSpace(poc.Expression)
	if expr == "" {
		return false
	}
	if strings.Contains(expr, "!") || strings.Contains(expr, " in ") || strings.Contains(expr, "[") {
		return true
	}
	return false
}

func appendRuleNames(left, right []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range append(append([]string{}, left...), right...) {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func dedupeRuleSets(in [][]string) [][]string {
	seen := map[string]bool{}
	var out [][]string
	for _, set := range in {
		key := strings.Join(set, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, set)
	}
	return out
}

func sortedRuleKeys(rules map[string]convert.XrayRule) []string {
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func isQuoted(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 2 && (s[0] == '"' || s[0] == '\'' || strings.HasPrefix(s, "r'") || strings.HasPrefix(s, `r"`))
}

func headerFromContains(value string) (string, string) {
	if idx := strings.IndexByte(value, ':'); idx > 0 {
		name := strings.TrimSpace(value[:idx])
		headerValue := strings.TrimSpace(value[idx+1:])
		if headerValue == "" {
			headerValue = "1"
		}
		return canonicalHeaderName(name), headerValue
	}
	return "X-Harness", value
}

func headerVarName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
}

func canonicalHeaderName(part string) string {
	part = strings.ReplaceAll(part, "_", "-")
	parts := strings.Split(part, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}

func isHeaderPart(part string) bool {
	switch part {
	case "", "body", "title", "status_code", "duration", "latency", "response", "request", "matched":
		return false
	default:
		return true
	}
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	match := re.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(match[1]))
}
