package convert

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spaolacci/murmur3"

	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
)

func TestRuntimeEquivalence_OutputVariableChain(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-output
detail:
  fingerprint:
    name: Runtime Output
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("app.abc123.js")
    output:
      search: '"src=\"(?P<asset>/static/app\.[a-z0-9]+\.js)\"".submatch(response.body_string)'
      asset_path: search["asset"]
  fetch_asset:
    request:
      method: GET
      path: /{{asset_path}}
    expression: response.body_string.contains("boot complete")
expression: discover() && fetch_asset()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<script src="/static/app.abc123.js"></script>`)
		case "/static/app.abc123.js", "//static/app.abc123.js":
			fmt.Fprint(w, "boot complete")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_PayloadExpansion(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-payload
detail:
  fingerprint:
    name: Runtime Payload
transport: http
payloads:
  payloads:
    p0:
      value: '""'
    p1:
      value: '"admin/login"'
rules:
  r0:
    request:
      method: GET
      path: /{{value}}
    expression: response.body_string.contains("payload-hit")
expression: r0()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/login" {
			fmt.Fprint(w, "payload-hit")
			return
		}
		fmt.Fprint(w, "miss")
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_SetVariable(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-set
detail:
  fingerprint:
    name: Runtime Set
transport: http
set:
  randomPath: get404Path()
rules:
  r0:
    request:
      method: GET
      path: /{{randomPath}}
      follow_redirects: false
    expression: response.status == 404 && response.body_string.contains("synthetic 404")
expression: r0()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "synthetic 404")
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_RawOutputPathMayStartWithSlash(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-raw-output-path
detail:
  fingerprint:
    name: Runtime Raw Output Path
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("location")
    output:
      search: r'location="(?P<nextpath>[\/\w]+)'.submatch(response.body_string)
      nextpath: search["nextpath"]
  follow:
    request:
      method: GET
      path: /{{nextpath}}
    expression: response.body_string.contains("followed")
expression: discover() && follow()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `location="/next"`)
		case "/next", "//next":
			fmt.Fprint(w, "followed")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_FaviconHashLink(t *testing.T) {
	iconBody := []byte("equivalence-icon")
	iconHash := xrayRuntimeFaviconHash(iconBody)
	xray := fmt.Sprintf(`
name: fingerprint-test--runtime-favicon
detail:
  fingerprint:
    name: Runtime Favicon
transport: http
rules:
  favicon_hash:
    request:
      method: GET
      path: /
    expression: faviconHash(response.getIconContent()) == %s
expression: favicon_hash()
`, iconHash)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><link rel="shortcut icon" href="/custom.ico"></head></html>`)
		case "/custom.ico":
			_, _ = w.Write(iconBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_MMH3IconInListAndFallback(t *testing.T) {
	iconBody := []byte("fallback-icon")
	iconHash := xrayRuntimeFaviconHash(iconBody)
	xray := fmt.Sprintf(`
name: fingerprint-test--runtime-mmh3-icon
detail:
  fingerprint:
    name: Runtime MMH3 Icon
transport: http
rules:
  favicon_hash:
    request:
      method: GET
      path: /
    expression: mmh3(icon(response)) in [111, %s, 222]
expression: favicon_hash()
`, iconHash)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body>no explicit icon</body></html>`)
		case "/favicon.ico":
			_, _ = w.Write(iconBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_StringTitleAndLiteralContains(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-title-string
detail:
  fingerprint:
    name: Runtime Title String
transport: http
rules:
  title_rule:
    request:
      method: GET
      path: /
    expression: string(response.title).contains("Sindoh") && string(response.title).contains("Printer")
  literal_false:
    request:
      method: GET
      path: /
    expression: '"a".contains("b")'
expression: title_rule() || literal_false()
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Sindoh Printer</title></head><body>title only</body></html>`)
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func TestRuntimeEquivalence_CertSubjectAndTimeConvert(t *testing.T) {
	xray := `
name: fingerprint-test--runtime-cert
detail:
  fingerprint:
    name: Runtime Cert
transport: http
rules:
  cert_rule:
    request:
      method: GET
      path: /
    expression: response.cert.subject.icontains("Acme Co") && timeConvert(response.cert.not_before, "2006-01-02 03:04:05").icontains("1970-01-01 12:00:00")
expression: cert_rule()
`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls ok")
	}))
	defer server.Close()

	assertRuntimeEquivalent(t, xray, server.URL)
}

func assertRuntimeEquivalent(t *testing.T, xrayYAML, baseURL string) {
	t.Helper()

	xrayMatched, err := executeXrayRuntime(xrayYAML, baseURL)
	if err != nil {
		t.Fatalf("execute xray model: %v", err)
	}
	neutronMatched, converted := executeConvertedRuntime(t, xrayYAML, baseURL)
	if xrayMatched != neutronMatched {
		t.Fatalf("runtime inequivalent: xray=%v neutron=%v\nconverted:\n%s", xrayMatched, neutronMatched, converted)
	}
}

func executeConvertedRuntime(t *testing.T, xrayYAML, baseURL string) (bool, string) {
	t.Helper()

	converted, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	var tmpl templates.Template
	if err := yaml.Unmarshal(converted, &tmpl); err != nil {
		t.Fatalf("unmarshal converted template: %v\n%s", err, converted)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile converted template: %v\n%s", err, converted)
	}
	result, err := tmpl.Execute(baseURL, nil)
	if err != nil {
		t.Fatalf("execute converted template: %v\n%s", err, converted)
	}
	return result != nil && result.Matched, string(converted)
}

func executeXrayRuntime(pocYAML, baseURL string) (bool, error) {
	var poc XrayPOC
	if err := yaml.Unmarshal([]byte(pocYAML), &poc); err != nil {
		return false, err
	}

	vars := deterministicXraySet(poc.Set)
	payloadRows := xrayPayloadRows(poc.Payloads)
	ruleResults := map[string]bool{}
	for _, ruleName := range orderedRuleNames(&poc) {
		rule := poc.Rules[ruleName]
		matched, err := executeXrayRule(baseURL, &rule, vars, payloadRows)
		if err != nil {
			return false, fmt.Errorf("%s: %v", ruleName, err)
		}
		ruleResults[ruleName] = matched
	}
	return evalTopExpr(poc.Expression, ruleResults), nil
}

func orderedRuleNames(poc *XrayPOC) []string {
	topExpr := parseTopExpression(poc.Expression)
	if topExpr == nil {
		return sortedKeys(poc.Rules)
	}
	seen := map[string]bool{}
	var names []string
	for _, name := range collectRuleNames(topExpr) {
		if seen[name] {
			continue
		}
		if _, ok := poc.Rules[name]; ok {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names
}

func executeXrayRule(baseURL string, rule *XrayRule, vars map[string]string, payloadRows []map[string]string) (bool, error) {
	if len(payloadRows) == 0 {
		payloadRows = []map[string]string{{}}
	}
	for _, payloads := range payloadRows {
		values := mergeStringMaps(vars, payloads)
		resp, err := requestXrayRule(baseURL, rule, values)
		if err != nil {
			return false, err
		}
		matched := xrayEval(rule.Expression, resp)
		if matched {
			applyXrayRuntimeOutput(rule.Output, resp, vars)
			return true, nil
		}
	}
	return false, nil
}

func requestXrayRule(baseURL string, rule *XrayRule, values map[string]string) (mockResponse, error) {
	method := rule.Request.Method
	if method == "" {
		method = http.MethodGet
	}
	reqPath := rule.Request.Path
	if reqPath == "" {
		reqPath = "/"
	}
	reqPath = replaceXrayPlaceholders(reqPath, values)
	target, err := joinURL(baseURL, reqPath)
	if err != nil {
		return mockResponse{}, err
	}
	body := replaceXrayPlaceholders(rule.Request.Body, values)
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		return mockResponse{}, err
	}
	for key, value := range rule.Request.Headers {
		req.Header.Set(key, replaceXrayPlaceholders(value, values))
	}

	client := &http.Client{}
	if strings.HasPrefix(target, "https://") {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	if !followRedirectsOrDefault(rule.Request.FollowRedirects) {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return mockResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	headers := map[string]string{}
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}
	if hash := xrayRuntimeFaviconHash(data); hash != "" {
		headers["__body_favicon_hash"] = hash
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		headers["__cert_subject"] = cert.Subject.String()
		headers["__cert_not_before"] = cert.NotBefore.Format("2006-01-02 03:04:05")
	}
	if resp.Request != nil && resp.Request.URL != nil {
		if hashes := xrayRuntimeIconHashes(client, resp.Request.URL, string(data), headers["__body_favicon_hash"]); len(hashes) > 0 {
			headers["__favicon_hash"] = strings.Join(hashes, "\n")
		}
	}
	return mockResponse{StatusCode: resp.StatusCode, Body: string(data), Headers: headers}, nil
}

func xrayRuntimeIconHashes(client *http.Client, base *url.URL, body, bodyHash string) []string {
	seen := map[string]struct{}{}
	hashes := map[string]struct{}{}
	addHash := func(hash string) {
		if hash != "" {
			hashes[hash] = struct{}{}
		}
	}
	for _, iconURL := range xrayRuntimeDiscoverIconURLs(base, body) {
		if _, ok := seen[iconURL]; ok {
			continue
		}
		seen[iconURL] = struct{}{}
		if iconURL == base.String() {
			addHash(bodyHash)
			continue
		}
		resp, err := client.Get(iconURL)
		if err != nil {
			continue
		}
		iconBody, _ := ioutil.ReadAll(resp.Body)
		_ = resp.Body.Close()
		addHash(xrayRuntimeFaviconHash(iconBody))
	}
	out := make([]string, 0, len(hashes))
	for hash := range hashes {
		out = append(out, hash)
	}
	sort.Strings(out)
	return out
}

func xrayRuntimeDiscoverIconURLs(base *url.URL, body string) []string {
	seen := map[string]struct{}{}
	var urls []string
	add := func(raw string) {
		raw = strings.TrimSpace(html.UnescapeString(raw))
		if raw == "" {
			return
		}
		ref, err := url.Parse(raw)
		if err != nil {
			return
		}
		resolved := base.ResolveReference(ref).String()
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		urls = append(urls, resolved)
	}
	for _, tag := range xrayRuntimeLinkTagRE.FindAllString(body, -1) {
		rel := xrayRuntimeAttr(tag, "rel")
		if strings.Contains(strings.ToLower(rel), "icon") {
			add(xrayRuntimeAttr(tag, "href"))
		}
	}
	add("/favicon.ico")
	return urls
}

func xrayRuntimeAttr(tag, name string) string {
	for _, match := range xrayRuntimeAttrRE.FindAllStringSubmatch(tag, -1) {
		if len(match) >= 4 && strings.EqualFold(match[1], name) {
			if match[2] != "" {
				return match[2]
			}
			return match[3]
		}
	}
	return ""
}

func xrayRuntimeFaviconHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	var wrapped strings.Builder
	for len(encoded) > 76 {
		wrapped.WriteString(encoded[:76])
		wrapped.WriteByte('\n')
		encoded = encoded[76:]
	}
	wrapped.WriteString(encoded)
	wrapped.WriteByte('\n')

	hasher := murmur3.New32WithSeed(0)
	_, _ = hasher.Write([]byte(wrapped.String()))
	return fmt.Sprintf("%d", int32(hasher.Sum32()))
}

var (
	xrayRuntimeLinkTagRE = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	xrayRuntimeAttrRE    = regexp.MustCompile(`(?is)\b([a-z0-9_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

func deterministicXraySet(set map[string]interface{}) map[string]string {
	vars := map[string]string{}
	for key, raw := range set {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		switch {
		case strings.EqualFold(expr, "get404Path()"):
			vars[key] = "xray-equivalence-404"
		case strings.HasPrefix(expr, "randomLowercase("):
			vars[key] = "abcdefgh"
		case strings.HasPrefix(expr, "randomInt("):
			vars[key] = "123456"
		default:
			vars[key] = normalizeXrayScalar(expr)
		}
	}
	return vars
}

func xrayPayloadRows(root XrayPayloadRoot) []map[string]string {
	if len(root.Payloads) == 0 {
		return nil
	}
	rowKeys := make([]string, 0, len(root.Payloads))
	for key := range root.Payloads {
		rowKeys = append(rowKeys, key)
	}
	sortPayloadRows(rowKeys)

	rows := make([]map[string]string, 0, len(rowKeys))
	for _, rowKey := range rowKeys {
		row := map[string]string{}
		for name, value := range root.Payloads[rowKey] {
			row[name] = normalizeXrayScalar(fmt.Sprint(value))
		}
		rows = append(rows, row)
	}
	return rows
}

func applyXrayRuntimeOutput(output map[string]interface{}, resp mockResponse, vars map[string]string) {
	if len(output) == 0 {
		return
	}
	sources := map[string]map[string]string{}
	for name, raw := range output {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if specs := findSubmatchSpecs(expr); len(specs) > 0 {
			sources[name] = extractNamedGroups(specs[0], resp)
		}
	}

	for name, raw := range output {
		expr := strings.TrimSpace(fmt.Sprint(raw))
		if specs := findSubmatchSpecs(expr); len(specs) > 0 && specs[0].GroupName != "" {
			groups := extractNamedGroups(specs[0], resp)
			if value := groups[specs[0].GroupName]; value != "" {
				vars[name] = value
			}
			continue
		}
		if source, group, ok := outputSourceReference(expr); ok {
			if value := sources[source][group]; value != "" {
				vars[name] = value
			}
			continue
		}
	}
}

func extractNamedGroups(spec submatchSpec, resp mockResponse) map[string]string {
	result := map[string]string{}
	re, err := regexp.Compile(spec.Pattern)
	if err != nil {
		return result
	}
	corpus := responsePartForRuntime(spec.Part, resp)
	match := re.FindStringSubmatch(corpus)
	if len(match) == 0 {
		return result
	}
	for idx, name := range re.SubexpNames() {
		if idx > 0 && name != "" && idx < len(match) {
			result[name] = match[idx]
		}
	}
	return result
}

func responsePartForRuntime(part string, resp mockResponse) string {
	switch part {
	case "", "body":
		return resp.Body
	case "header", "all_headers":
		return buildRawHeader(resp.Headers)
	default:
		return getHeader(resp.Headers, part)
	}
}

func replaceXrayPlaceholders(s string, values map[string]string) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(match string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(match, "{{"), "}}")
		name = strings.TrimSpace(name)
		if value, ok := values[name]; ok {
			return value
		}
		return match
	})
}

func mergeStringMaps(left, right map[string]string) map[string]string {
	merged := map[string]string{}
	for key, value := range left {
		merged[key] = value
	}
	for key, value := range right {
		merged[key] = value
	}
	return merged
}

func joinURL(baseURL, reqPath string) (string, error) {
	if strings.HasPrefix(reqPath, "http://") || strings.HasPrefix(reqPath, "https://") {
		return reqPath, nil
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(reqPath, "/") {
		reqPath = "/" + reqPath
	}
	parsed.Path = reqPath
	parsed.RawQuery = ""
	return parsed.String(), nil
}
