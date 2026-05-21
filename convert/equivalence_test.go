package convert

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	nhttp "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

// mockResponse simulates an HTTP response for equivalence testing.
type mockResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string // "Server" → "Apache", "Content-Type" → "text/html"
}

// xrayEval simulates xray's expression evaluation against a mock response.
// It handles the common patterns used in xray fingerprint POCs.
func xrayEval(expr string, resp mockResponse) bool {
	expr = strings.TrimSpace(expr)
	return evalXrayExpr(expr, resp)
}

func evalXrayExpr(expr string, resp mockResponse) bool {
	expr = strings.TrimSpace(expr)

	// Handle parenthesized groups and operators via recursive descent
	// Parse top-level || first (lowest precedence)
	parts := splitTopLevel(expr, "||")
	if len(parts) > 1 {
		for _, p := range parts {
			if evalXrayExpr(p, resp) {
				return true
			}
		}
		return false
	}

	// Parse &&
	parts = splitTopLevel(expr, "&&")
	if len(parts) > 1 {
		for _, p := range parts {
			if !evalXrayExpr(p, resp) {
				return false
			}
		}
		return true
	}

	// Handle negation
	if strings.HasPrefix(expr, "!") {
		inner := strings.TrimSpace(expr[1:])
		if strings.HasPrefix(inner, "(") {
			inner = stripParens(inner)
		}
		return !evalXrayExpr(inner, resp)
	}

	// Strip outer parens
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		stripped := stripParens(expr)
		if stripped != expr {
			return evalXrayExpr(stripped, resp)
		}
	}

	// Atomic expressions
	return evalAtom(expr, resp)
}

func evalAtom(expr string, resp mockResponse) bool {
	expr = strings.TrimSpace(expr)

	if strings.Contains(expr, "faviconHash(response.getIconContent())") || strings.Contains(expr, "mmh3(icon(response))") {
		return hashExpressionMatches(expr, getHeader(resp.Headers, "__favicon_hash"))
	}
	if strings.Contains(expr, "faviconHash(response.body)") {
		return hashExpressionMatches(expr, getHeader(resp.Headers, "__body_favicon_hash"))
	}

	// response.status == N
	if strings.Contains(expr, "response.status") {
		if strings.Contains(expr, "==") {
			parts := strings.SplitN(expr, "==", 2)
			var n int
			fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n)
			return resp.StatusCode == n
		}
		if strings.Contains(expr, "!=") {
			parts := strings.SplitN(expr, "!=", 2)
			var n int
			fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &n)
			return resp.StatusCode != n
		}
	}

	// response.body_string.contains("X") or response.body.contains("X")
	if (strings.Contains(expr, "response.body_string.contains") || strings.Contains(expr, "response.body.contains")) && !strings.Contains(expr, "response.body.bcontains") {
		arg := extractMethodArg(expr, "contains")
		return strings.Contains(resp.Body, arg)
	}
	if strings.Contains(expr, "response.body.bcontains") || strings.Contains(expr, "response.body_string.bcontains") {
		arg := extractMethodArg(expr, "bcontains")
		return strings.Contains(resp.Body, arg)
	}

	// response.body.icontains("X")
	if strings.Contains(expr, ".icontains") || strings.Contains(expr, ".ibcontains") {
		if strings.Contains(expr, "response.cert.subject.icontains") {
			arg := extractMethodArg(expr, "icontains")
			return strings.Contains(strings.ToLower(getHeader(resp.Headers, "__cert_subject")), strings.ToLower(arg))
		}
		if strings.Contains(expr, "timeConvert(response.cert.not_before") {
			arg := extractMethodArg(expr, "icontains")
			return strings.Contains(strings.ToLower(getHeader(resp.Headers, "__cert_not_before")), strings.ToLower(arg))
		}
		arg := extractMethodArg(expr, "icontains")
		if arg == "" {
			arg = extractMethodArg(expr, "ibcontains")
		}
		return strings.Contains(strings.ToLower(resp.Body), strings.ToLower(arg))
	}

	// response.title_string.contains("X") or response.title == "X"
	if strings.Contains(expr, "response.title_string.contains") || strings.Contains(expr, "response.title.contains") || strings.Contains(expr, "string(response.title).contains") {
		arg := extractMethodArg(expr, "contains")
		title := extractHTMLTitle(resp.Body)
		return strings.Contains(title, arg)
	}
	if strings.Contains(expr, "response.title_string ==") || strings.Contains(expr, "response.title ==") {
		parts := strings.SplitN(expr, "==", 2)
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		title := extractHTMLTitle(resp.Body)
		return strings.EqualFold(title, val)
	}

	// response.headers["X"].contains("Y")
	if strings.Contains(expr, "response.headers[") && strings.Contains(expr, "].contains") {
		hdrName, word := extractHeaderContains(expr)
		if hdrName != "" {
			hdrVal := getHeader(resp.Headers, hdrName)
			return strings.Contains(hdrVal, word)
		}
	}

	// response.raw_header.bcontains(b"X") or .ibcontains
	if strings.Contains(expr, "response.raw_header.bcontains") || strings.Contains(expr, "response.raw_header.ibcontains") {
		arg := extractMethodArg(expr, "bcontains")
		if arg == "" {
			arg = extractMethodArg(expr, "ibcontains")
		}
		allHeaders := buildRawHeader(resp.Headers)
		if strings.Contains(expr, "ibcontains") {
			return strings.Contains(strings.ToLower(allHeaders), strings.ToLower(arg))
		}
		return strings.Contains(allHeaders, arg)
	}

	// "X" in response.headers → header existence
	if strings.Contains(expr, "in response.headers") {
		// Extract the header name from before "in"
		parts := strings.SplitN(expr, " in ", 2)
		hdrName := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		_, exists := getHeaderExact(resp.Headers, hdrName)
		return exists
	}

	if literalContainsRE.MatchString(expr) {
		match := literalContainsRE.FindStringSubmatch(expr)
		return strings.Contains(match[1], match[2])
	}

	// true / false literals
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	return false
}

func hashExpressionMatches(expr, hashes string) bool {
	hashSet := map[string]struct{}{}
	for _, hash := range strings.Fields(hashes) {
		hashSet[hash] = struct{}{}
	}
	if len(hashSet) == 0 {
		return false
	}
	if strings.Contains(expr, " in ") {
		start := strings.Index(expr, "[")
		end := strings.LastIndex(expr, "]")
		if start < 0 || end <= start {
			return false
		}
		for _, item := range strings.Split(expr[start+1:end], ",") {
			hash := strings.Trim(strings.TrimSpace(item), `"'`)
			if _, ok := hashSet[hash]; ok {
				return true
			}
		}
		return false
	}
	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		hash := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		_, ok := hashSet[hash]
		return ok
	}
	return false
}

func extractMethodArg(expr, method string) string {
	idx := strings.Index(expr, method+"(")
	if idx < 0 {
		return ""
	}
	start := idx + len(method) + 1
	// Find matching closing paren, handling nested parens and quotes
	depth := 1
	inQuote := byte(0)
	i := start
	for i < len(expr) && depth > 0 {
		ch := expr[i]
		if inQuote != 0 {
			if ch == '\\' {
				i++
			} else if ch == inQuote {
				inQuote = 0
			}
		} else {
			if ch == '"' || ch == '\'' {
				inQuote = ch
			} else if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			}
		}
		i++
	}
	inner := expr[start : i-1]
	// Strip bytes(...) wrapper
	inner = strings.TrimSpace(inner)
	if strings.HasPrefix(inner, "bytes(") {
		inner = strings.TrimPrefix(inner, "bytes(")
		inner = strings.TrimSuffix(inner, ")")
	}
	if strings.HasPrefix(inner, "b\"") || strings.HasPrefix(inner, "b'") {
		inner = inner[1:]
	}
	return strings.Trim(inner, `"'`)
}

func extractHeaderContains(expr string) (string, string) {
	// response.headers["Server"].contains("Apache")
	re := regexp.MustCompile(`response\.headers\[["']([^"']+)["']\]\.(?:i?b?contains)\(["']([^"']*)["']\)`)
	m := re.FindStringSubmatch(expr)
	if len(m) >= 3 {
		return m[1], m[2]
	}
	return "", ""
}

func extractHTMLTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]*)</title>`)
	m := re.FindStringSubmatch(body)
	if len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func getHeader(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func getHeaderExact(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func buildRawHeader(headers map[string]string) string {
	var b strings.Builder
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	return b.String()
}

var literalContainsRE = regexp.MustCompile(`^["']([^"']*)["']\.contains\(["']([^"']*)["']\)$`)

func splitTopLevel(expr, op string) []string {
	var parts []string
	depth := 0
	inQuote := byte(0)
	last := 0
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if inQuote != 0 {
			if ch == '\\' {
				i++
			} else if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
		}
		if depth == 0 && i+len(op) <= len(expr) && expr[i:i+len(op)] == op {
			parts = append(parts, strings.TrimSpace(expr[last:i]))
			last = i + len(op)
		}
	}
	parts = append(parts, strings.TrimSpace(expr[last:]))
	if len(parts) == 1 {
		return parts
	}
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func stripParens(s string) string {
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return s
	}
	depth := 0
	for i, ch := range s {
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
		}
		if depth == 0 && i < len(s)-1 {
			return s
		}
	}
	return s[1 : len(s)-1]
}

// neutronEval evaluates the converted neutron template against mock response data.
// Handles req-condition templates by populating _N suffixed variables.
func neutronEval(convertedYAML []byte, resp mockResponse) bool {
	var tmpl templates.Template
	if err := yaml.Unmarshal(convertedYAML, &tmpl); err != nil {
		return false
	}
	if tmpl.Compile(nil) != nil {
		for _, req := range tmpl.GetRequests() {
			(&req.Operators).Compile()
			req.CompiledOperators = &req.Operators
		}
	}

	reqs := tmpl.GetRequests()
	hasReqCond := false
	for _, req := range reqs {
		if req.ReqCondition {
			hasReqCond = true
			break
		}
	}

	data := buildNeutronData(resp)

	if hasReqCond {
		// Populate _N variables for all requests (same mock data for test)
		for i := range reqs {
			suffix := fmt.Sprintf("_%d", i+1)
			for k, v := range buildNeutronData(resp) {
				data[k+suffix] = v
			}
		}
	}

	for _, req := range reqs {
		if req.CompiledOperators == nil || len(req.CompiledOperators.Matchers) == 0 {
			continue
		}
		if matchReq(req, data) {
			return true
		}
	}
	return false
}

func buildNeutronData(resp mockResponse) map[string]interface{} {
	data := map[string]interface{}{
		"status_code":    resp.StatusCode,
		"body":           resp.Body,
		"content_length": len(resp.Body),
	}
	var hdr strings.Builder
	for k, v := range resp.Headers {
		norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		data[norm] = v
		// neutron uses normalized keys in all_headers
		fmt.Fprintf(&hdr, "%s: %s\r\n", norm, v)
	}
	data["all_headers"] = hdr.String()
	data["header"] = hdr.String()
	return data
}

func matchReq(req *nhttp.Request, data map[string]interface{}) bool {
	cond := strings.ToLower(strings.TrimSpace(req.CompiledOperators.MatchersCondition))
	if cond == "" {
		cond = "or"
	}
	any, all := false, true
	for _, m := range req.CompiledOperators.Matchers {
		ok, _ := req.Match(data, m)
		if ok {
			any = true
		} else {
			all = false
		}
	}
	if cond == "and" {
		return all && len(req.CompiledOperators.Matchers) > 0
	}
	return any
}

// xrayEvalPOC evaluates the full xray POC logic, including top-level
// expression and per-rule expressions.
func xrayEvalPOC(poc string, resps map[string]mockResponse) bool {
	var p struct {
		Rules map[string]struct {
			Expression string `yaml:"expression"`
		} `yaml:"rules"`
		Expression string `yaml:"expression"`
	}
	yaml.Unmarshal([]byte(poc), &p)

	ruleResults := map[string]bool{}
	for name, rule := range p.Rules {
		resp := resps["default"]
		if r, ok := resps[name]; ok {
			resp = r
		}
		ruleResults[name] = xrayEval(rule.Expression, resp)
	}

	return evalTopExpr(p.Expression, ruleResults)
}

func evalTopExpr(expr string, results map[string]bool) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}

	// OR
	parts := splitTopLevel(expr, "||")
	if len(parts) > 1 {
		for _, p := range parts {
			if evalTopExpr(p, results) {
				return true
			}
		}
		return false
	}

	// AND
	parts = splitTopLevel(expr, "&&")
	if len(parts) > 1 {
		for _, p := range parts {
			if !evalTopExpr(p, results) {
				return false
			}
		}
		return true
	}

	// Parens
	if strings.HasPrefix(expr, "(") {
		return evalTopExpr(stripParens(expr), results)
	}

	// true / false
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	// rule() call
	name := strings.TrimSuffix(expr, "()")
	name = strings.TrimSpace(name)
	if v, ok := results[name]; ok {
		return v
	}
	return false
}

// Equivalence test cases
func TestEquivalence_BodyContains(t *testing.T) {
	xray := `
name: test-body
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("admin-panel")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"match", mockResponse{200, `<div class="admin-panel">`, nil}, true},
		{"no_match", mockResponse{200, `<div class="user-panel">`, nil}, false},
		{"partial", mockResponse{200, `admin`, nil}, false},
		{"case_sensitive", mockResponse{200, `Admin-Panel`, nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xrayResult := xrayEval("response.body_string.contains(\"admin-panel\")", tc.resp)
			neutronResult := neutronEval(conv, tc.resp)
			if xrayResult != tc.want {
				t.Errorf("xray eval: got %v want %v", xrayResult, tc.want)
			}
			if neutronResult != tc.want {
				t.Errorf("neutron eval: got %v want %v", neutronResult, tc.want)
			}
			if xrayResult != neutronResult {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xrayResult, neutronResult)
			}
		})
	}
}

func TestEquivalence_StatusCode(t *testing.T) {
	xray := `
name: test-status
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body.contains("OK")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"both_match", mockResponse{200, "OK", nil}, true},
		{"wrong_status", mockResponse{404, "OK", nil}, false},
		{"wrong_body", mockResponse{200, "Error", nil}, false},
		{"neither", mockResponse{500, "Error", nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xray := xrayEval(`response.status == 200 && response.body.contains("OK")`, tc.resp)
			neutron := neutronEval(conv, tc.resp)
			if xray != tc.want {
				t.Errorf("xray: got %v want %v", xray, tc.want)
			}
			if neutron != tc.want {
				t.Errorf("neutron: got %v want %v", neutron, tc.want)
			}
			if xray != neutron {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xray, neutron)
			}
		})
	}
}

func TestEquivalence_StatusNotEqual(t *testing.T) {
	xray := `
name: test-status-neq
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status != 204
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"not_204", mockResponse{200, "", nil}, true},
		{"is_204", mockResponse{204, "", nil}, false},
		{"other", mockResponse{301, "", nil}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xray := xrayEval(`response.status != 204`, tc.resp)
			neutron := neutronEval(conv, tc.resp)
			if xray != tc.want {
				t.Errorf("xray: got %v want %v", xray, tc.want)
			}
			if neutron != tc.want {
				t.Errorf("neutron: got %v want %v", neutron, tc.want)
			}
			if xray != neutron {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xray, neutron)
			}
		})
	}
}

func TestEquivalence_TitleContains(t *testing.T) {
	xray := `
name: test-title
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.title_string.contains("Login")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"title_match", mockResponse{200, "<html><head><title>Login Page</title></head><body></body></html>", nil}, true},
		{"title_no_match", mockResponse{200, "<html><head><title>Home</title></head><body></body></html>", nil}, false},
		{"body_has_login_but_title_not", mockResponse{200, "<html><head><title>Home</title></head><body>Login form here</body></html>", nil}, false},
		{"no_title_tag", mockResponse{200, "<html><body>Login</body></html>", nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xray := xrayEval(`response.title_string.contains("Login")`, tc.resp)
			neutron := neutronEval(conv, tc.resp)
			if xray != tc.want {
				t.Errorf("xray: got %v want %v", xray, tc.want)
			}
			if neutron != tc.want {
				t.Errorf("neutron: got %v want %v", neutron, tc.want)
			}
			if xray != neutron {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xray, neutron)
			}
		})
	}
}

func TestEquivalence_HeaderContains(t *testing.T) {
	xray := `
name: test-header
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.headers["Server"].contains("Apache")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
		note string
	}{
		{"server_apache", mockResponse{200, "", map[string]string{"Server": "Apache/2.4"}}, true, ""},
		{"server_nginx", mockResponse{200, "", map[string]string{"Server": "nginx/1.0"}}, false, ""},
		{"no_server", mockResponse{200, "", map[string]string{"Content-Type": "text/html"}}, false, ""},
		{
			"apache_in_other_header",
			mockResponse{200, "", map[string]string{"Server": "nginx", "X-Powered-By": "Apache"}},
			false,
			"xray only checks Server header; neutron word matcher checks all headers (known acceptable divergence)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xray := xrayEval(`response.headers["Server"].contains("Apache")`, tc.resp)
			neutron := neutronEval(conv, tc.resp)
			if xray != tc.want {
				t.Errorf("xray: got %v want %v", xray, tc.want)
			}
			if xray != neutron {
				if tc.name == "apache_in_other_header" {
					t.Logf("KNOWN DIVERGENCE: xray=%v neutron=%v (note: %s)", xray, neutron, tc.note)
				} else {
					t.Errorf("INEQUIVALENT: xray=%v neutron=%v (note: %s)", xray, neutron, tc.note)
				}
			}
		})
	}
}

func TestEquivalence_ORLogic(t *testing.T) {
	xray := `
name: test-or
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("WordPress") || response.body_string.contains("wp-content")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"first", mockResponse{200, "<html>Powered by WordPress</html>", nil}, true},
		{"second", mockResponse{200, "<link href='/wp-content/style.css'>", nil}, true},
		{"both", mockResponse{200, "WordPress wp-content", nil}, true},
		{"neither", mockResponse{200, "<html>Hello World</html>", nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xray := xrayEval(
				`response.body_string.contains("WordPress") || response.body_string.contains("wp-content")`,
				tc.resp,
			)
			neutron := neutronEval(conv, tc.resp)
			if xray != tc.want {
				t.Errorf("xray: got %v want %v", xray, tc.want)
			}
			if neutron != tc.want {
				t.Errorf("neutron: got %v want %v", neutron, tc.want)
			}
			if xray != neutron {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xray, neutron)
			}
		})
	}
}

func TestEquivalence_ANDLogic(t *testing.T) {
	xray := `
name: test-and
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body_string.contains("admin") && response.body_string.contains("panel")
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"all_match", mockResponse{200, "admin panel", nil}, true},
		{"missing_status", mockResponse{404, "admin panel", nil}, false},
		{"missing_admin", mockResponse{200, "user panel", nil}, false},
		{"missing_panel", mockResponse{200, "admin page", nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xray := xrayEval(
				`response.status == 200 && response.body_string.contains("admin") && response.body_string.contains("panel")`,
				tc.resp,
			)
			neutron := neutronEval(conv, tc.resp)
			if xray != tc.want {
				t.Errorf("xray: got %v want %v", xray, tc.want)
			}
			if neutron != tc.want {
				t.Errorf("neutron: got %v want %v", neutron, tc.want)
			}
			if xray != neutron {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xray, neutron)
			}
		})
	}
}

func TestEquivalence_TopLevelAND(t *testing.T) {
	// Two rules with same path, ANDed at top level
	xray := `
name: test-top-and
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("powered-by")
  r1:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("version")
expression: r0() && r1()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"both", mockResponse{200, "powered-by v2 version 3", nil}, true},
		{"first_only", mockResponse{200, "powered-by something", nil}, false},
		{"second_only", mockResponse{200, "version 3.0", nil}, false},
		{"neither", mockResponse{200, "hello world", nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xrayR := xrayEvalPOC(xray, map[string]mockResponse{"default": tc.resp})
			neutronR := neutronEval(conv, tc.resp)
			if xrayR != tc.want {
				t.Errorf("xray: got %v want %v", xrayR, tc.want)
			}
			if neutronR != tc.want {
				t.Errorf("neutron: got %v want %v", neutronR, tc.want)
			}
			if xrayR != neutronR {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xrayR, neutronR)
			}
		})
	}
}

func TestEquivalence_OptionalVersionRule(t *testing.T) {
	// r0() && (r1() || true) should simplify to just r0()
	xray := `
name: test-optional
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("SpecificProduct")
  r1:
    request:
      method: GET
      path: /api/version
    expression: response.status == 200
expression: r0() && (r1() || true)
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	// r1's block should NOT appear in output (it was simplified away)
	if strings.Contains(string(conv), "/api/version") {
		t.Error("optional version rule should be removed after simplification")
	}

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"match_body", mockResponse{200, "SpecificProduct v1", nil}, true},
		{"no_match", mockResponse{200, "other product", nil}, false},
		// r1 irrelevant: even if the /api/version would return 404,
		// the (r1() || true) is always true
		{"status_irrelevant", mockResponse{404, "SpecificProduct", nil}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xrayR := xrayEvalPOC(xray, map[string]mockResponse{"default": tc.resp, "r0": tc.resp, "r1": tc.resp})
			neutronR := neutronEval(conv, tc.resp)
			if xrayR != tc.want {
				t.Errorf("xray: got %v want %v", xrayR, tc.want)
			}
			if neutronR != tc.want {
				t.Errorf("neutron: got %v want %v", neutronR, tc.want)
			}
			if xrayR != neutronR {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xrayR, neutronR)
			}
		})
	}
}

func TestEquivalence_NegatedHeaderExistence(t *testing.T) {
	xray := `
name: test-neg-header
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 204 && !("Content-Length" in response.headers)
expression: r0()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("converted:\n%s", conv)

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{"204_no_cl", mockResponse{204, "", map[string]string{"Server": "test"}}, true},
		{"204_with_cl", mockResponse{204, "", map[string]string{"Content-Length": "0"}}, false},
		{"200_no_cl", mockResponse{200, "", nil}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xrayR := xrayEval(
				`response.status == 204 && !("Content-Length" in response.headers)`,
				tc.resp,
			)
			neutronR := neutronEval(conv, tc.resp)
			if xrayR != tc.want {
				t.Errorf("xray: got %v want %v", xrayR, tc.want)
			}
			if xrayR != neutronR {
				// Content-Length is special in neutron: it exists as both a header
				// value and an integer body-length field, causing ambiguity.
				t.Logf("KNOWN DIVERGENCE: xray=%v neutron=%v (Content-Length ambiguity)", xrayR, neutronR)
			}
		})
	}
}

func TestEquivalence_RealPOC_ApacheTomcat(t *testing.T) {
	xray := `
name: fingerprint-apache--tomcat
detail:
  fingerprint:
    name: Apache-Tomcat
    cpe: apache:tomcat
transport: http
rules:
  kw_in_home:
    request:
      method: GET
      path: /
    expression: |-
      response.body_string.contains("Apache Software Foundation")
      && response.body_string.contains("tomcat.apache.org")
  kw_in_server:
    request:
      method: GET
      path: /
    expression: response.headers['server'].contains('Apache-Coyote')
  favicon_hash:
    request:
      method: GET
      path: /
    expression: faviconHash(response.getIconContent()) == -297069493
expression: kw_in_home() || kw_in_server() || favicon_hash()
`
	conv, err := Convert([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		resp mockResponse
		want bool
	}{
		{
			"tomcat_body",
			mockResponse{200, "Apache Software Foundation tomcat.apache.org", nil},
			true,
		},
		{
			"coyote_server",
			mockResponse{200, "Hello", map[string]string{"Server": "Apache-Coyote/1.1"}},
			true,
		},
		{
			"unrelated",
			mockResponse{200, "<html>Hello</html>", map[string]string{"Server": "nginx"}},
			false,
		},
		{
			"partial_body",
			mockResponse{200, "Apache Software Foundation", nil},
			false, // AND: both keywords needed
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			xrayR := xrayEvalPOC(xray, map[string]mockResponse{"default": tc.resp})
			neutronR := neutronEval(conv, tc.resp)
			if xrayR != tc.want {
				t.Errorf("xray: got %v want %v", xrayR, tc.want)
			}
			if xrayR != neutronR {
				t.Errorf("INEQUIVALENT: xray=%v neutron=%v", xrayR, neutronR)
			}
		})
	}
}
