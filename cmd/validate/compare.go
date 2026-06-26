package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Xray POC schema
// ---------------------------------------------------------------------------

type xrayRequest struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Cache           bool              `yaml:"cache"`
}

type xrayRule struct {
	Request    xrayRequest `yaml:"request"`
	Expression string      `yaml:"expression"`
}

type xrayPOC struct {
	Name       string                 `yaml:"name"`
	Detail     map[string]interface{} `yaml:"detail"`
	Rules      map[string]xrayRule    `yaml:"rules"`
	Expression string                 `yaml:"expression"`
	Transport  string                 `yaml:"transport"`
}

// ---------------------------------------------------------------------------
// Mock response + report
// ---------------------------------------------------------------------------

type mockResponse struct {
	Name       string            `json:"name"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

type caseResult struct {
	MockName     string        `json:"mock_name"`
	Mock         *mockResponse `json:"mock,omitempty"`
	XrayResult   bool          `json:"xray_result"`
	NucleiResult bool          `json:"nuclei_result"`
	Consistent   bool          `json:"consistent"`
	XrayError    string        `json:"xray_error,omitempty"`
	NucleiError  string        `json:"nuclei_error,omitempty"`
}

type ruleResult struct {
	Name        string       `json:"name"`
	NucleiIndex int          `json:"nuclei_index"`
	XrayExpr    string       `json:"xray_expr"`
	Cases       []caseResult `json:"cases"`
	Consistent  bool         `json:"consistent"`
}

type report struct {
	XrayPath       string       `json:"xray_path"`
	NucleiPath     string       `json:"nuclei_path"`
	XrayName       string       `json:"xray_name"`
	NucleiID       string       `json:"nuclei_id"`
	XrayRuleCount  int          `json:"xray_rule_count"`
	NucleiReqCount int          `json:"nuclei_req_count"`
	CountMatch     bool         `json:"count_match"`
	Rules          []ruleResult `json:"rules"`
	TotalCases     int          `json:"total_cases"`
	Passed         int          `json:"passed"`
	Failed         int          `json:"failed"`
	Consistent     bool         `json:"consistent"`
	Warnings       []string     `json:"warnings,omitempty"`
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func runCompare(args []string) {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	var (
		xrayPath   string
		nucleiPath string
		jsonOut    bool
		verbose    bool
	)
	fs.StringVar(&xrayPath, "xray", "", "path to xray POC YAML")
	fs.StringVar(&nucleiPath, "nuclei", "", "path to nuclei/neutron template YAML")
	fs.BoolVar(&jsonOut, "json", false, "emit JSON report")
	fs.BoolVar(&verbose, "v", false, "verbose output (include mock dumps)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  validate compare --xray <xray.yml> --nuclei <nuclei.yaml> [--json] [-v]")
		fmt.Fprintln(os.Stderr, "  validate compare <xray.yml> <nuclei.yaml> [--json] [-v]")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if xrayPath == "" && fs.NArg() >= 1 {
		xrayPath = fs.Arg(0)
	}
	if nucleiPath == "" && fs.NArg() >= 2 {
		nucleiPath = fs.Arg(1)
	}
	if xrayPath == "" || nucleiPath == "" {
		fs.Usage()
		os.Exit(2)
	}

	xray, err := loadXray(xrayPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load xray: %v\n", err)
		os.Exit(1)
	}
	tpl, err := loadNuclei(nucleiPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load nuclei: %v\n", err)
		os.Exit(1)
	}

	rep := compareVerify(xray, tpl, xrayPath, nucleiPath, verbose)

	if jsonOut {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
	} else {
		printText(rep, verbose)
	}
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

func loadXray(path string) (xrayPOC, error) {
	var poc xrayPOC
	data, err := os.ReadFile(path)
	if err != nil {
		return poc, err
	}
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return poc, fmt.Errorf("parse yaml: %w", err)
	}
	return poc, nil
}

func loadNuclei(path string) (*templates.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t := &templates.Template{}
	if err := yaml.Unmarshal(data, t); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	// Try the canonical compile first. If it fails (e.g. unsafe requests, missing
	// executer options), fall back to compiling only the matchers on each HTTP
	// request so verification can still proceed.
	if err := t.Compile(nil); err != nil {
		for _, req := range t.GetRequests() {
			if compileErr := (&req.Operators).Compile(); compileErr != nil {
				return nil, fmt.Errorf("compile matchers: %w (template compile: %v)", compileErr, err)
			}
			req.CompiledOperators = &req.Operators
		}
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

type rulePair struct {
	name     string
	xrayRule xrayRule
	req      *http.Request
	idx      int
}

func compareVerify(xray xrayPOC, tpl *templates.Template, xrayPath, nucleiPath string, verbose bool) report {
	rep := report{
		XrayPath:       xrayPath,
		NucleiPath:     nucleiPath,
		XrayName:       xray.Name,
		NucleiID:       tpl.Id,
		XrayRuleCount:  len(xray.Rules),
		NucleiReqCount: len(tpl.GetRequests()),
		Consistent:     true,
	}
	rep.CountMatch = rep.XrayRuleCount == rep.NucleiReqCount
	if !rep.CountMatch {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("rule count mismatch: xray=%d nuclei=%d — pairing only the first %d",
				rep.XrayRuleCount, rep.NucleiReqCount, min(rep.XrayRuleCount, rep.NucleiReqCount)))
	}

	pairs, keyWarnings := pairRules(xray, tpl)
	rep.Warnings = append(rep.Warnings, keyWarnings...)

	for _, p := range pairs {
		rr := ruleResult{
			Name:        p.name,
			NucleiIndex: p.idx,
			XrayExpr:    p.xrayRule.Expression,
			Consistent:  true,
		}
		mocks := generateMocks(p.xrayRule, p.req)
		for _, m := range mocks {
			cr := evaluateCase(p.xrayRule.Expression, p.req, m)
			if verbose {
				mCopy := m
				cr.Mock = &mCopy
			}
			rep.TotalCases++
			if cr.Consistent {
				rep.Passed++
			} else {
				rep.Failed++
				rr.Consistent = false
				rep.Consistent = false
			}
			rr.Cases = append(rr.Cases, cr)
		}
		rep.Rules = append(rep.Rules, rr)
	}
	return rep
}

func pairRules(xray xrayPOC, tpl *templates.Template) ([]rulePair, []string) {
	var warnings []string
	reqs := tpl.GetRequests()
	if len(xray.Rules) == 0 || len(reqs) == 0 {
		return nil, warnings
	}

	keys := make([]string, 0, len(xray.Rules))
	for k := range xray.Rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Warn if keys don't look like r0/r1/... (ordering may not match nuclei http order).
	rRe := regexp.MustCompile(`^r\d+$`)
	for _, k := range keys {
		if !rRe.MatchString(k) {
			warnings = append(warnings,
				fmt.Sprintf("xray rule key %q is not r<digit> form; pairing by lexical order may differ from nuclei http[] order", k))
			break
		}
	}

	n := len(keys)
	if len(reqs) < n {
		n = len(reqs)
	}
	pairs := make([]rulePair, 0, n)
	for i := 0; i < n; i++ {
		pairs = append(pairs, rulePair{
			name:     keys[i],
			xrayRule: xray.Rules[keys[i]],
			req:      reqs[i],
			idx:      i,
		})
	}
	return pairs, warnings
}

func evaluateCase(expr string, req *http.Request, m mockResponse) caseResult {
	cr := caseResult{MockName: m.Name}
	xrayOK, xrayErr := evalXray(expr, m)
	nucleiOK, nucleiErr := evalNuclei(req, m)
	cr.XrayResult = xrayOK
	cr.NucleiResult = nucleiOK
	if xrayErr != nil {
		cr.XrayError = xrayErr.Error()
	}
	if nucleiErr != nil {
		cr.NucleiError = nucleiErr.Error()
	}
	cr.Consistent = (xrayOK == nucleiOK) && cr.XrayError == "" && cr.NucleiError == ""
	return cr
}

// ---------------------------------------------------------------------------
// Xray evaluation
// ---------------------------------------------------------------------------

var (
	// strip `b"..."` prefix on byte-literal arguments
	reBytesLiteral = regexp.MustCompile(`b"([^"\\]*(?:\\.[^"\\]*)*)"`)
	// response.headers["Name"] — capture Name
	reHeaderRef = regexp.MustCompile(`response\.headers\[\"([^\"]+)\"\]`)
	// response.body.contains / .bcontains / .matches / .icontains — and header variants
	reMethodCall = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\.(contains|icontains|bcontains|matches|startsWith|endsWith)\(`)
	// header-subscript method calls, captured separately because the lhs has a dot
	reHeaderMethodCall = regexp.MustCompile(`xray_hdr_[A-Za-z0-9_]+\.(contains|icontains|bcontains|matches|startsWith|endsWith)\(`)
)

// normalizeXrayExpr rewrites xray DSL into a govaluate-compatible expression.
func normalizeXrayExpr(expr string) string {
	out := expr
	// b"..." -> "..."
	out = reBytesLiteral.ReplaceAllString(out, `"$1"`)

	// response.headers["Set-Cookie"] -> xray_hdr_set_cookie
	out = reHeaderRef.ReplaceAllStringFunc(out, func(match string) string {
		m := reHeaderRef.FindStringSubmatch(match)
		return headerVarName(m[1])
	})

	// response.body_string -> response.body (body_string is xray's regex-target alias)
	out = strings.ReplaceAll(out, "response.body_string", "response.body")

	// dotted identifiers -> flat vars (order matters: content_type before body)
	out = strings.ReplaceAll(out, "response.content_type", "xray_content_type")
	out = strings.ReplaceAll(out, "response.status", "xray_status")
	out = strings.ReplaceAll(out, "response.body", "xray_body")

	// Escape embedded single quotes inside double-quoted literals. govaluate
	// tokenizes 'abc' inside "x'abc'y" as a separate STRING token and raises
	// "No parameter 'abc' found". Escaping with \' prevents that.
	out = escapeSingleQuotesInsideDoubleStrings(out)

	// ident.method( ... ) -> method(ident, ...
	out = reMethodCall.ReplaceAllStringFunc(out, func(match string) string {
		parts := reMethodCall.FindStringSubmatch(match)
		ident, method := parts[1], parts[2]
		fn := mapXrayMethod(method)
		if fn == "regex" {
			// regex(pattern, target): pattern is the arg, target is ident — swap
			return fmt.Sprintf("regex(@@PATTERN@@__%s__", ident)
		}
		return fmt.Sprintf("%s(%s, ", fn, ident)
	})

	// Finalize regex swaps: regex(@@PATTERN@@__ident__<args>) -> regex(<args>, ident)
	// After replacement the content between the marker and the matching ')' is the
	// original pattern argument; restore it to the canonical form.
	out = fixRegexSwap(out)

	return out
}

// escapeSingleQuotesInsideDoubleStrings scans s and, for every double-quoted
// literal, replaces each unescaped ' with \'. Characters outside double quotes
// are emitted unchanged. Backslash escape sequences are honored.
func escapeSingleQuotesInsideDoubleStrings(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '"' {
			out.WriteByte(c)
			i++
			for i < len(s) {
				c = s[i]
				if c == '\\' && i+1 < len(s) {
					out.WriteByte(c)
					out.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '\'' {
					out.WriteString(`\'`)
					i++
					continue
				}
				out.WriteByte(c)
				i++
				if c == '"' {
					break
				}
			}
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

func mapXrayMethod(m string) string {
	switch m {
	case "contains", "bcontains":
		return "contains"
	case "icontains":
		return "icontains"
	case "matches":
		return "regex"
	case "startsWith":
		return "starts_with"
	case "endsWith":
		return "ends_with"
	}
	return m
}

// fixRegexSwap turns "regex(@@PATTERN@@__ident__<pat>)" into "regex(<pat>, ident)".
func fixRegexSwap(s string) string {
	const marker = "regex(@@PATTERN@@__"
	for {
		i := strings.Index(s, marker)
		if i < 0 {
			return s
		}
		identStart := i + len(marker)
		identEnd := strings.Index(s[identStart:], "__")
		if identEnd < 0 {
			return s
		}
		ident := s[identStart : identStart+identEnd]
		// Find the matching ')' for this regex(
		openIdx := i + len("regex(") - 1
		close := matchingParen(s, openIdx)
		if close < 0 {
			return s
		}
		argStart := identStart + identEnd + 2 // skip trailing "__"
		args := s[argStart:close]
		rebuilt := fmt.Sprintf("regex(%s, %s)", args, ident)
		s = s[:i] + rebuilt + s[close+1:]
	}
}

// matchingParen returns the index of the ')' matching the '(' at open.
func matchingParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
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

func headerVarName(name string) string {
	n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"))
	return "xray_hdr_" + n
}

func evalXray(expr string, m mockResponse) (bool, error) {
	if strings.TrimSpace(expr) == "" {
		return true, nil
	}
	norm := normalizeXrayExpr(expr)
	e, err := govaluate.NewEvaluableExpressionWithFunctions(norm, common.GetHelperFunctions())
	if err != nil {
		return false, fmt.Errorf("compile xray expr: %w (normalized: %s)", err, norm)
	}
	params := buildXrayParams(expr, m)
	res, err := e.Evaluate(params)
	if err != nil {
		return false, fmt.Errorf("evaluate xray expr: %w", err)
	}
	b, ok := res.(bool)
	if !ok {
		return false, fmt.Errorf("xray expr did not return bool (got %T)", res)
	}
	return b, nil
}

// buildXrayParams assembles the govaluate variable map. It seeds defaults for
// every header identifier referenced in the original expression so that absent
// headers simply evaluate to empty strings instead of raising "no parameter".
func buildXrayParams(origExpr string, m mockResponse) map[string]interface{} {
	p := map[string]interface{}{
		"xray_status":       float64(m.StatusCode),
		"xray_body":         m.Body,
		"xray_content_type": m.Headers["Content-Type"],
	}
	// Seed empty defaults for every header name the expression references.
	for _, hm := range reHeaderRef.FindAllStringSubmatch(origExpr, -1) {
		p[headerVarName(hm[1])] = ""
	}
	// Overlay the actual mock headers.
	for k, v := range m.Headers {
		p[headerVarName(k)] = v
	}
	return p
}

// ---------------------------------------------------------------------------
// Nuclei evaluation (delegates to neutron's http.Request.Match)
// ---------------------------------------------------------------------------

func evalNuclei(req *http.Request, m mockResponse) (bool, error) {
	if req.CompiledOperators == nil || len(req.CompiledOperators.Matchers) == 0 {
		return false, fmt.Errorf("nuclei request has no compiled matchers")
	}
	data := buildNucleiData(m)

	condition := strings.ToLower(strings.TrimSpace(req.CompiledOperators.MatchersCondition))
	if condition == "" {
		condition = "or"
	}

	var anyMatched, allMatched = false, true
	for _, matcher := range req.CompiledOperators.Matchers {
		ok, _ := req.Match(data, matcher)
		if ok {
			anyMatched = true
		} else {
			allMatched = false
		}
	}
	if condition == "and" {
		return allMatched, nil
	}
	return anyMatched, nil
}

func buildNucleiData(m mockResponse) map[string]interface{} {
	data := make(map[string]interface{}, 8+len(m.Headers))
	data["status_code"] = m.StatusCode // must be int (Request.Match does .(int))
	data["body"] = m.Body
	data["host"] = "example.com"
	data["type"] = "http"
	data["matched"] = "http://example.com/"
	data["content_length"] = len(m.Body)

	var allHeaders strings.Builder
	for k, v := range m.Headers {
		lk := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		data[lk] = v
		fmt.Fprintf(&allHeaders, "%s: %s\r\n", lk, v)
	}
	data["all_headers"] = allHeaders.String()
	data["header"] = allHeaders.String()
	return data
}

// ---------------------------------------------------------------------------
// Mock generation
// ---------------------------------------------------------------------------

func generateMocks(rule xrayRule, req *http.Request) []mockResponse {
	hdrConstraints := extractXrayHeaderConstraints(rule.Expression)
	bodyNeedles := extractXrayBodyConstraints(rule.Expression)
	bodyMinLen := extractXrayBodyLengthMin(rule.Expression)

	// Positive status: prefer xray == N, else nuclei status matcher, else 200.
	status := extractXrayStatus(rule.Expression)
	if status == 0 {
		status = firstNucleiStatus(req)
	}
	if status == 0 {
		status = 200
	}

	// Target-side needles (extracted from nuclei matchers). Used both for
	// satisfying positive mocks and for generating drop_tgt_* variants that
	// catch cases where the nuclei template has a constraint the xray side
	// does NOT require (source=T, target=F).
	tgtBody, tgtHeaderWords, tgtStatuses := extractNucleiNeedles(req)

	headers := buildPositiveHeaders(hdrConstraints, req)
	body := buildPositiveBody(req, bodyNeedles, bodyMinLen)

	positive := mockResponse{
		Name:       "positive",
		StatusCode: status,
		Headers:    headers,
		Body:       body,
	}

	wrongStatus := positive
	wrongStatus.Name = "wrong_status"
	wrongStatus.Headers = cloneMap(headers)
	if status == 500 {
		wrongStatus.StatusCode = 404
	} else {
		wrongStatus.StatusCode = 500
	}

	emptyBody := positive
	emptyBody.Name = "empty_body"
	emptyBody.Headers = cloneMap(headers)
	emptyBody.Body = ""

	missingHeaders := positive
	missingHeaders.Name = "missing_headers"
	missingHeaders.Headers = map[string]string{}

	mocks := []mockResponse{positive, wrongStatus, emptyBody, missingHeaders}

	// --- drop-source: one xray needle removed, everything else kept ----------
	// Catches "nuclei doesn't check this needle but xray does" (source=F, target=T).
	for i, needle := range bodyNeedles {
		partial := positive
		partial.Name = fmt.Sprintf("drop_body[%d]=%s", i, shortLabel(needle))
		partial.Headers = cloneMap(headers)
		// Strip both the literal and its lowercase form; some nuclei matchers
		// compare against a lowercased header block, re-injecting case variants.
		stripped := strings.ReplaceAll(body, needle, "")
		stripped = strings.ReplaceAll(stripped, strings.ToLower(needle), "")
		partial.Body = stripped
		mocks = append(mocks, partial)
	}
	hdrIdx := 0
	for name, needles := range hdrConstraints {
		for _, needle := range needles {
			partial := positive
			partial.Name = fmt.Sprintf("drop_hdr[%d]=%s/%s", hdrIdx, name, shortLabel(needle))
			hdrIdx++
			reduced := make(map[string][]string, len(hdrConstraints))
			for k, vs := range hdrConstraints {
				if k == name {
					reduced[k] = dropFirst(vs, needle)
				} else {
					reduced[k] = vs
				}
			}
			rebuilt := buildPositiveHeaders(reduced, req)
			needleLower := strings.ToLower(needle)
			for k, v := range rebuilt {
				v = strings.ReplaceAll(v, needle, "")
				v = strings.ReplaceAll(v, needleLower, "")
				rebuilt[k] = v
			}
			partial.Headers = rebuilt
			mocks = append(mocks, partial)
		}
	}

	// --- drop-target: one nuclei needle removed -----------------------------
	// Catches "xray doesn't require this constraint but nuclei does"
	// (source=T, target=F). Applied only for needles NOT already present in
	// the source-side list — otherwise the mock would be identical to drop-src.
	srcBodySet := toSet(bodyNeedles)
	srcHdrSet := map[string]bool{}
	for _, ns := range hdrConstraints {
		for _, n := range ns {
			srcHdrSet[strings.ToLower(n)] = true
		}
	}
	for i, needle := range tgtBody {
		if srcBodySet[needle] {
			continue
		}
		partial := positive
		partial.Name = fmt.Sprintf("drop_tgt_body[%d]=%s", i, shortLabel(needle))
		partial.Headers = cloneMap(headers)
		stripped := strings.ReplaceAll(body, needle, "")
		stripped = strings.ReplaceAll(stripped, strings.ToLower(needle), "")
		partial.Body = stripped
		mocks = append(mocks, partial)
	}
	for i, needle := range tgtHeaderWords {
		if srcHdrSet[strings.ToLower(needle)] {
			continue
		}
		partial := positive
		partial.Name = fmt.Sprintf("drop_tgt_hdr[%d]=%s", i, shortLabel(needle))
		// Rebuild headers without re-injecting this nuclei word via X-Mock.
		rebuilt := buildPositiveHeaders(hdrConstraints, nil) // nil skips tgt injection
		needleLower := strings.ToLower(needle)
		for k, v := range rebuilt {
			v = strings.ReplaceAll(v, needle, "")
			v = strings.ReplaceAll(v, needleLower, "")
			rebuilt[k] = v
		}
		partial.Headers = rebuilt
		mocks = append(mocks, partial)
	}

	// --- solo-source: body/headers contain ONLY one source needle -----------
	// Catches "nuclei treats a needle as sufficient but xray requires it in
	// conjunction with others". Critical for AND-composed xray rules.
	for i, needle := range bodyNeedles {
		partial := positive
		partial.Name = fmt.Sprintf("solo_body[%d]=%s", i, shortLabel(needle))
		partial.Headers = map[string]string{}
		partial.Body = needle
		mocks = append(mocks, partial)
	}
	soloIdx := 0
	for name, needles := range hdrConstraints {
		for _, needle := range needles {
			partial := positive
			partial.Name = fmt.Sprintf("solo_hdr[%d]=%s/%s", soloIdx, name, shortLabel(needle))
			soloIdx++
			partial.Headers = map[string]string{name: synthesizeHeaderValue(name, []string{needle})}
			partial.Body = ""
			mocks = append(mocks, partial)
		}
	}

	// --- alt-status: for each non-positive status in nuclei matcher list ----
	// Catches "nuclei accepts multiple statuses but xray requires a specific one".
	for i, s := range tgtStatuses {
		if s == status {
			continue
		}
		partial := positive
		partial.Name = fmt.Sprintf("alt_status[%d]=%d", i, s)
		partial.Headers = cloneMap(headers)
		partial.StatusCode = s
		mocks = append(mocks, partial)
	}

	return mocks
}

// extractNucleiNeedles collects body/header words and status codes from all
// compiled nuclei matchers. Words for "part: all" are emitted for both body
// and header channels conservatively.
func extractNucleiNeedles(req *http.Request) (body, header []string, statuses []int) {
	if req == nil || req.CompiledOperators == nil {
		return
	}
	for _, m := range req.CompiledOperators.Matchers {
		switch m.Type {
		case "status":
			statuses = append(statuses, m.Status...)
		case "word":
			part := m.Part
			if part == "" {
				part = "body"
			}
			switch part {
			case "body":
				body = append(body, m.Words...)
			case "header":
				header = append(header, m.Words...)
			case "all":
				body = append(body, m.Words...)
				header = append(header, m.Words...)
			}
		case "regex":
			part := m.Part
			if part == "" {
				part = "body"
			}
			for _, pat := range m.Regex {
				hint := regexLiteralHint(pat)
				if hint == "" {
					continue
				}
				if part == "header" || part == "all" {
					header = append(header, hint)
				}
				if part == "body" || part == "all" || part == "" {
					body = append(body, hint)
				}
			}
		}
	}
	return
}

// regexLiteralHint returns the longest plain-char substring of a regex pattern,
// used as a best-effort hint for mock generation.
func regexLiteralHint(pat string) string {
	stripped := pat
	for _, r := range []string{"^", "$", "(?i)", "(?s)", "(?m)", "\\b", "\\B"} {
		stripped = strings.ReplaceAll(stripped, r, "")
	}
	var best, cur strings.Builder
	flush := func() {
		if cur.Len() > best.Len() {
			best.Reset()
			best.WriteString(cur.String())
		}
		cur.Reset()
	}
	for _, ch := range stripped {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == ' ' ||
			ch >= 0x4e00 && ch <= 0x9fff {
			cur.WriteRune(ch)
		} else {
			flush()
		}
	}
	flush()
	return strings.TrimSpace(best.String())
}

func toSet(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// dropFirst returns a copy of xs with the first occurrence of v removed.
func dropFirst(xs []string, v string) []string {
	out := make([]string, 0, len(xs))
	dropped := false
	for _, x := range xs {
		if !dropped && x == v {
			dropped = true
			continue
		}
		out = append(out, x)
	}
	return out
}

// shortLabel returns a short printable label for a needle, preserving non-ASCII
// (e.g. CJK) so mock names stay distinguishable. Long strings are truncated.
func shortLabel(s string) string {
	r := []rune(s)
	if len(r) > 12 {
		r = append(r[:12], '…')
	}
	// Replace whitespace so the label stays tabular-friendly.
	out := strings.Map(func(c rune) rune {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			return '_'
		}
		return c
	}, string(r))
	if out == "" {
		return "x"
	}
	return out
}

// extractXrayHeaderConstraints collects header → value fragments for each
// response.headers["X"].contains("Y") / .bcontains(...) in the expression.
// Multiple constraints for the same header are concatenated.
func extractXrayHeaderConstraints(expr string) map[string][]string {
	re := regexp.MustCompile(`response\.headers\["([^"]+)"\]\.[b]?contains\(b?"([^"]+)"\)`)
	out := map[string][]string{}
	for _, m := range re.FindAllStringSubmatch(expr, -1) {
		name, val := m[1], m[2]
		out[name] = append(out[name], val)
	}
	// Also respect content_type.contains(...)
	reCT := regexp.MustCompile(`response\.content_type\.[b]?contains\(b?"([^"]+)"\)`)
	for _, m := range reCT.FindAllStringSubmatch(expr, -1) {
		out["Content-Type"] = append(out["Content-Type"], m[1])
	}
	return out
}

func extractXrayBodyConstraints(expr string) []string {
	re := regexp.MustCompile(`response\.body(?:_string)?\.[b]?contains\(b?"([^"]+)"\)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(expr, -1) {
		out = append(out, m[1])
	}
	return out
}

func extractXrayBodyLengthMin(expr string) int {
	re := regexp.MustCompile(`len\(response\.body\)\s*>\s*(\d+)`)
	m := re.FindStringSubmatch(expr)
	if m == nil {
		return 0
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	return n + 1
}

func extractXrayStatus(expr string) int {
	re := regexp.MustCompile(`response\.status\s*==\s*(\d+)`)
	m := re.FindStringSubmatch(expr)
	if m == nil {
		return 0
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	return n
}

func firstNucleiStatus(req *http.Request) int {
	if req.CompiledOperators == nil {
		return 0
	}
	for _, m := range req.CompiledOperators.Matchers {
		if m.Type == "status" && len(m.Status) > 0 {
			return m.Status[0]
		}
	}
	return 0
}

// buildPositiveHeaders synthesizes a headers map that satisfies all xray
// header constraints AND makes nuclei header-part word matchers true.
func buildPositiveHeaders(constraints map[string][]string, req *http.Request) map[string]string {
	hdr := make(map[string]string)
	for name, needles := range constraints {
		hdr[name] = synthesizeHeaderValue(name, needles)
	}

	// Ensure nuclei header-part word matchers can find their words somewhere.
	if req != nil && req.CompiledOperators != nil {
		for _, m := range req.CompiledOperators.Matchers {
			if m.Type != "word" {
				continue
			}
			part := m.Part
			if part != "header" && part != "all" {
				continue
			}
			for _, w := range m.Words {
				if headerBlockContains(hdr, w) {
					continue
				}
				// Stuff into a mock header. Using all-lowercase so the key
				// survives nuclei's name-normalization (hyphens -> underscores)
				// without drift.
				key := "X-Mock"
				hdr[key] = strings.TrimSpace(hdr[key] + " " + w)
			}
		}
	}
	return hdr
}

func headerBlockContains(hdr map[string]string, needle string) bool {
	// Reproduce nuclei's all_headers normalization for a faithful check.
	for k, v := range hdr {
		lk := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(k), "-", "_"))
		line := lk + ": " + v
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func synthesizeHeaderValue(name string, needles []string) string {
	joined := strings.Join(needles, "_")
	switch strings.ToLower(name) {
	case "set-cookie":
		return joined + "=abc123; Path=/"
	case "location":
		return "/path/" + joined + "/redir"
	case "www-authenticate":
		return `Basic realm="` + joined + `"`
	case "content-type":
		return needles[0]
	case "server":
		return "mock-" + joined
	}
	return "prefix-" + joined + "-suffix"
}

// buildPositiveBody collects words that must appear in the body for nuclei
// matchers to pass, then appends xray body needles. Pads with spaces if a
// minimum length constraint was specified.
func buildPositiveBody(req *http.Request, xrayNeedles []string, minLen int) string {
	var tokens []string
	if req.CompiledOperators != nil {
		for _, m := range req.CompiledOperators.Matchers {
			if m.Type != "word" {
				continue
			}
			part := m.Part
			if part == "" {
				part = "body"
			}
			if part != "body" && part != "all" {
				continue
			}
			tokens = append(tokens, m.Words...)
		}
		// For regex matchers on body, include a literal prefix heuristic so
		// simple patterns hit. We leave complex patterns to be handled by the
		// author — divergence here is itself informative.
		for _, m := range req.CompiledOperators.Matchers {
			if m.Type != "regex" {
				continue
			}
			part := m.Part
			if part == "" {
				part = "body"
			}
			if part != "body" && part != "all" {
				continue
			}
			for _, pat := range m.Regex {
				tokens = append(tokens, regexLiteralHint(pat))
			}
		}
	}
	tokens = append(tokens, xrayNeedles...)

	body := strings.Join(tokens, " ")
	for len(body) < minLen {
		body += strings.Repeat(" ", minLen-len(body))
	}
	return body
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

func printText(r report, verbose bool) {
	fmt.Printf("pocverify: xray=%s nuclei=%s\n", r.XrayPath, r.NucleiPath)
	fmt.Printf("  xray name: %s   nuclei id: %s\n", r.XrayName, r.NucleiID)
	fmt.Printf("  xray rules: %d   nuclei requests: %d   count-match: %s\n",
		r.XrayRuleCount, r.NucleiReqCount, yesNo(r.CountMatch))

	for _, w := range r.Warnings {
		fmt.Printf("  ! %s\n", w)
	}

	for _, rr := range r.Rules {
		fmt.Printf("\nRule %s -> http[%d]\n", rr.Name, rr.NucleiIndex)
		expr := rr.XrayExpr
		if len(expr) > 140 {
			expr = expr[:140] + "…"
		}
		fmt.Printf("  xray expr: %s\n", expr)

		for _, c := range rr.Cases {
			tag := "PASS"
			if !c.Consistent {
				tag = "FAIL"
			}
			fmt.Printf("    [%s] %-32s xray=%s nuclei=%s\n",
				tag, c.MockName, boolT(c.XrayResult), boolT(c.NucleiResult))
			if c.XrayError != "" {
				fmt.Printf("           xray error: %s\n", c.XrayError)
			}
			if c.NucleiError != "" {
				fmt.Printf("           nuclei error: %s\n", c.NucleiError)
			}
			if verbose && c.Mock != nil {
				fmt.Printf("           mock: status=%d headers=%v body=%q\n",
					c.Mock.StatusCode, c.Mock.Headers, truncate(c.Mock.Body, 80))
			}
		}
		fmt.Printf("  rule consistent: %s\n", yesNo(rr.Consistent))
	}

	fmt.Printf("\nSummary: %d/%d consistent, %d divergent\n",
		r.Passed, r.TotalCases, r.Failed)
	overall := "CONSISTENT"
	if !r.Consistent {
		overall = "DIVERGENT"
	}
	fmt.Printf("Overall: %s\n", overall)
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func boolT(b bool) string {
	if b {
		return "T"
	}
	return "F"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
