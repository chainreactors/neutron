package http

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/protocols"
)

type requestGenerator struct {
	currentIndex     int
	currentPayloads  map[string]interface{}
	okCurrentPayload bool
	request          *Request
	input            *protocols.ScanContext
	payloadIterator  *protocols.Iterator
	rawRequest       *rawRequest
}

// newGenerator creates a NewGenerator request generator instance
func (r *Request) newGenerator(input *protocols.ScanContext) *requestGenerator {
	generator := &requestGenerator{
		request: r,
		input:   input,
	}
	var payloads map[string]interface{}
	if input != nil && len(input.Payloads) > 0 {
		payloads = input.Payloads
	}
	if len(payloads) > 0 {
		gen, err := protocols.NewGenerator(payloads, r.attackType)
		if err != nil {
			return nil
		}
		generator.payloadIterator = gen.NewIterator()
	} else if len(r.Payloads) > 0 {
		generator.payloadIterator = r.generator.NewIterator()
	}
	return generator
}

// nextValue returns the next path or the next raw request depending on user input
// It returns false if all the inputs have been exhausted by the generator instance.
func (r *requestGenerator) nextValue() (value string, payloads map[string]interface{}, result bool) {
	// Iterate each payload sequentially for each request path/raw
	//
	// If the sequence has finished for the current payload values
	// then restart the sequence from the beginning and move on to the next payloads values
	// otherwise use the last request.
	var sequence []string
	switch {
	case len(r.request.Path) > 0:
		sequence = r.request.Path
	case len(r.request.Raw) > 0:
		sequence = r.request.Raw
	default:
		return "", nil, false
	}

	hasPayloadIterator := r.payloadIterator != nil

	if hasPayloadIterator && r.currentPayloads == nil {
		r.currentPayloads, r.okCurrentPayload = r.payloadIterator.Value()
	}

	var request string
	var shouldContinue bool
	if nextRequest, nextIndex, found := r.findNextIteration(sequence, r.currentIndex); found {
		r.currentIndex = nextIndex + 1
		request = nextRequest
		shouldContinue = true
	} else {
		// if found is false which happens at end of iteration of reqData(path or raw request)
		// try again from start with index 0
		if nextRequest, nextIndex, found := r.findNextIteration(sequence, 0); found && hasPayloadIterator {
			r.currentIndex = nextIndex + 1
			request = nextRequest
			shouldContinue = true
		}
	}

	if shouldContinue {
		//if r.hasMarker(request, Once) {
		//	r.applyMark(request, Once)
		//}
		if hasPayloadIterator {
			return request, r.currentPayloads, r.okCurrentPayload
		}
		// next should return a copy of payloads and not pointer to payload to avoid data race
		return request, r.currentPayloads, true
	} else {
		return "", nil, false
	}
}

// findNextIteration iterates and returns next Request(path or raw request)
// at end of each iteration payload is incremented
func (r *requestGenerator) findNextIteration(sequence []string, index int) (string, int, bool) {
	for i, request := range sequence[index:] {
		//if r.wasMarked(request, Once) {
		//	// if request contains flowmark i.e `@once` and is marked skip it
		//	continue
		//}
		return request, index + i, true

	}
	// move on to next payload if current payload is applied/returned for all Requests(path or raw request)
	if r.payloadIterator != nil {
		r.currentPayloads, r.okCurrentPayload = r.payloadIterator.Value()
	}
	return "", 0, false
}

// Total returns the total number of requests for the generator
func (r *requestGenerator) Total() int {
	sequenceCount := len(r.request.Path)
	if len(r.request.Raw) > 0 {
		sequenceCount = len(r.request.Raw)
	}
	if r.payloadIterator != nil {
		return sequenceCount * r.payloadIterator.Remaining()
	}
	return sequenceCount
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(baseURL, reqdata string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// We get the next payload for the request.
	var err error
	allVars := common.MergeMaps(payloads, dynamicValues)
	for payloadName, payloadValue := range payloads {
		payloads[payloadName], err = common.Evaluate(common.ToString(payloadValue), allVars)
		if err != nil {
			return nil, err
		}
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	reqdata, parsed = baseURLWithTemplatePrefs(reqdata, parsed)
	isRawRequest := len(r.request.Raw) > 0

	trailingSlash := false
	if !isRawRequest && strings.HasSuffix(parsed.Path, "/") && strings.Contains(reqdata, "{{BaseURL}}/") {
		trailingSlash = true
	}
	targetValues := generateVariables(parsed, trailingSlash, pathPrefix(r.input))
	var globalVars map[string]interface{}
	if r.input != nil {
		globalVars = r.input.GlobalVars
	}
	if len(globalVars) > 0 {
		targetValues = common.MergeMaps(globalVars, targetValues)
	}
	values := common.MergeMaps(targetValues, allVars)
	if r.request.options != nil && r.request.options.Variables.Len() > 0 {
		variablesMap := r.request.options.Variables.Evaluate(values)
		// Override re-evaluated random/static variables with stable globalVars
		for k, v := range globalVars {
			if _, defined := variablesMap[k]; defined {
				variablesMap[k] = v
			}
		}
		if len(variablesMap) > 0 {
			allVars = common.MergeMaps(variablesMap, allVars)
			dynamicValues = common.MergeMaps(variablesMap, dynamicValues)
			values = common.MergeMaps(targetValues, allVars)
		}
	}
	reqdata, err = common.Evaluate(reqdata, common.MergeMaps(values, targetValues))
	if err != nil {
		return nil, err
	}
	if hasUnresolvedTemplate(reqdata, values) {
		return nil, errStopExecution
	}

	if isRawRequest {
		return r.makeHTTPRequestFromRaw(parsed.String(), reqdata, values, allVars)
	}

	return r.makeHTTPRequestFromModel(reqdata, values, allVars)
}

// baseURLWithTemplatePrefs returns the url for BaseURL keeping
// the template port and path preference over the user provided one.
func baseURLWithTemplatePrefs(data string, parsed *url.URL) (string, *url.URL) {
	// template port preference over input URL port if template has a port
	matches := urlWithPortRegex.FindAllStringSubmatch(data, -1)
	if len(matches) == 0 {
		return data, parsed
	}
	port := matches[0][1]
	parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	data = strings.Replace(data, ":"+port, "", -1)
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return data, parsed
}

//func (r *Request) executeRequest(reqURL string, request *generatedRequest, previous output.InternalEvent, requestCount int) error {
//}

// MakeHTTPRequestFromModel creates a *http.Request from a request template
func (r *requestGenerator) makeHTTPRequestFromModel(data string, values, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// Build a request on the specified URL
	req, err := http.NewRequest(r.request.Method, data, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(r.request.Context())
	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}
	return &generatedRequest{request: request, original: r.request, dynamicValues: dynamicValues, meta: values}, nil
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *requestGenerator) makeHTTPRequestFromRaw(baseURL, data string, values, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// request values.
	var request *http.Request
	rawRequestData, err := parseRaw(data, baseURL, r.request.Unsafe)
	if err != nil {
		return nil, err
	}

	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		request, err = rawRequestData.makeRequest()
		if err != nil {
			return nil, err
		}
		unsafeReq := &generatedRequest{request: request, meta: values, dynamicValues: dynamicValues, original: r.request}
		return unsafeReq, nil
	}

	// retryablehttp
	//var body io.ReadCloser
	//body = ioutil.NopCloser(strings.NewReader(rawRequestData.Data))

	req, err := http.NewRequest(rawRequestData.Method, rawRequestData.FullURL, strings.NewReader(rawRequestData.Data))
	if err != nil {
		return nil, err
	}
	for key, value := range rawRequestData.Headers {
		if key == "" {
			continue
		}
		req.Header[key] = []string{value}
		if key == "Host" {
			req.Host = value
		}
	}
	request, err = r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}

	generatedRequest := &generatedRequest{
		request:       request,
		meta:          values,
		original:      r.request,
		dynamicValues: dynamicValues,
	}

	if reqWithAnnotations, hasAnnotations := r.request.parseAnnotations(data, req); hasAnnotations {
		generatedRequest.request = reqWithAnnotations
	} else {
		generatedRequest.request = request.WithContext(r.request.Context())
	}

	return generatedRequest, nil
}

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *http.Request, values map[string]interface{}) (*http.Request, error) {
	// Set the header values requested
	for header, value := range r.request.Headers {
		value, err := common.Evaluate(value, values)
		if err != nil {
			return nil, err
		}
		if hasUnresolvedTemplate(value, values) {
			return nil, errStopExecution
		}
		req.Header[header] = []string{value}
		if header == "Host" {
			req.Host = value
		}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	//if r.request.Threads <= 0 && req.Header.Get("Connection") == "" {
	//	req.Close = true
	//}

	// Check if the user requested a request body
	if r.request.Body != "" {
		body := r.request.Body
		body, err := common.Evaluate(body, values)
		if err != nil {
			return nil, err
		}
		if hasUnresolvedTemplate(body, values) {
			return nil, errStopExecution
		}
		req.Body = NopCloser(strings.NewReader(body))
	}
	//if !r.request.Unsafe {
	//	setHeader(req, "User-Agent", common.GetRandom())
	//}

	// Only set these headers on non-raw requests
	//if len(r.request.Raw) == 0 && !r.request.Unsafe {
	//	setHeader(req, "Accept", "*/*")
	//	setHeader(req, "Accept-Language", "en")
	//}

	return req, nil
}

var (
	templateExpressionRE = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)
	simpleIdentifierRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func hasUnresolvedTemplate(value string, values map[string]interface{}) bool {
	if !strings.Contains(value, "{{") || !strings.Contains(value, "}}") {
		return false
	}
	for _, match := range templateExpressionRE.FindAllStringSubmatch(value, -1) {
		if len(match) < 2 {
			continue
		}
		if isUnresolvedNeutronExpression(strings.TrimSpace(match[1]), values) {
			return true
		}
	}
	return false
}

func isUnresolvedNeutronExpression(expr string, values map[string]interface{}) bool {
	if expr == "" {
		return false
	}
	if simpleIdentifierRE.MatchString(expr) {
		return true
	}
	if len(common.FindExpressions("{{"+expr+"}}", common.ParenthesisOpen, common.ParenthesisClose, values)) > 0 {
		return true
	}
	return false
}

//
//func (r *requestGenerator) newRawRequest(req *http.Request,rawreq rawRequest,values map[string]interface{})*http.Request{
//	rawreq = ReplaceRawRequest(rawreq,values)
//	req.header = rawreq.headers
//}

// setHeader sets some headers only if the header wasn't supplied by the user
func setHeader(req *http.Request, name, value string) {
	if _, ok := req.Header[name]; !ok {
		req.Header.Set(name, value)
	}
	if name == "Host" {
		req.Host = value
	}
}

// generateVariables will create default variables after parsing a url
func generateVariables(parsed *url.URL, trailingSlash bool, mountPrefix string) map[string]interface{} {
	domain := parsed.Host
	if strings.Contains(parsed.Host, ":") {
		domain = strings.Split(parsed.Host, ":")[0]
	}

	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else if parsed.Scheme == "http" {
			port = "80"
		}
	}

	if trailingSlash {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}

	escapedPath := parsed.EscapedPath()
	directory := path.Dir(escapedPath)
	if directory == "." {
		directory = ""
	}
	base := path.Base(escapedPath)
	if base == "." {
		base = ""
	}

	// RootURL gets the optional mount prefix appended so templates that compute
	// paths relative to "the app root" land under the sub-path the caller
	// declared. BaseURL stays untouched: it's the literal scan input, so
	// templates that reference {{BaseURL}}/foo keep behaving as before.
	rootURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, normalizePathPrefix(mountPrefix))

	httpVariables := map[string]interface{}{
		"BaseURL":  parsed.String(),
		"RootURL":  rootURL,
		"Hostname": parsed.Host,
		"Host":     domain,
		"Port":     port,
		"Path":     directory,
		"File":     base,
		"Scheme":   parsed.Scheme,
	}

	return common.MergeMaps(httpVariables, common.GenerateDNVariables(domain))
}

// pathPrefix pulls the optional mount-path prefix off the ScanContext. Nil
// input is the common case (in-process tests, no extra context) and yields
// "" so RootURL stays scheme://host.
func pathPrefix(input *protocols.ScanContext) string {
	if input == nil {
		return ""
	}
	return input.PathPrefix
}

// normalizePathPrefix canonicalises a mount-path prefix: empty/"/" become ""
// (no prefix), missing leading slash gets one prepended, trailing slashes are
// trimmed so the final RootURL doesn't end with "//" when a template appends
// a leading-slash path.
func normalizePathPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
}

