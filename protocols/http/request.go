package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/utils/encode"
)

var errStopExecution = errors.New("stop execution due to unresolved variables")

var _ protocols.Request = &Request{}

type Request struct {
	// operators for the current request go here.
	operators.Operators `json:",inline" yaml:",inline"`
	// Path contains the path/s for the request
	Path []string `json:"path,omitempty" yaml:"path,omitempty"`
	// Raw contains raw requests
	Raw []string `json:"raw,omitempty" yaml:"raw,omitempty"`
	ID  string   `json:"id,omitempty" yaml:"id,omitempty"`
	// Name is the name of the request
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `json:"attack,omitempty" yaml:"attack,omitempty"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `json:"method,omitempty" yaml:"method,omitempty"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `json:"body,omitempty" yaml:"body,omitempty"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `json:"payloads,omitempty" yaml:"payloads,omitempty"`
	// Headers contains headers to send with the request
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `json:"max-redirects,omitempty" yaml:"max-redirects,omitempty"`
	// PipelineConcurrentConnections is number of connections in pipelining
	//Threads int `json:"threads" yaml:"threads"`

	// MaxSize is the maximum size of http response body to read in bytes.
	MaxSize int `json:"max-size,omitempty" yaml:"max-size,omitempty"`

	// CookieReuse is kept for nuclei template compatibility; cookie reuse is
	// enabled by default for one scan execution unless DisableCookie is set.
	CookieReuse bool `json:"cookie-reuse,omitempty" yaml:"cookie-reuse,omitempty"`
	// DisableCookie disables cookie reuse for this request.
	DisableCookie bool `json:"disable-cookie,omitempty" yaml:"disable-cookie,omitempty"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `json:"redirects,omitempty" yaml:"redirects,omitempty"`
	//   This can be used in conjunction with `max-redirects` to control the HTTP request redirects.
	HostRedirects bool `yaml:"host-redirects,omitempty" json:"host-redirects,omitempty"`
	// Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining (race conditions/billions requests)
	// All requests must be indempotent (GET/POST)
	Unsafe bool `json:"unsafe,omitempty" yaml:"unsafe,omitempty"`
	// ReqCondition automatically assigns numbers to requests and preserves
	// their history for being matched at the end.
	// Currently only works with sequential http requests.
	ReqCondition bool `json:"req-condition,omitempty" yaml:"req-condition,omitempty"`
	// InternalMatchers marks this request's matchers as internal-only.
	// When true, matchers evaluate for extraction/condition purposes but
	// do not report Matched=true to the outer executor — only the final
	// request (without this flag) determines whether the template matches.
	InternalMatchers bool `json:"internal-matchers,omitempty" yaml:"internal-matchers,omitempty"`
	//   StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.
	StopAtFirstMatch bool `json:"stop-at-first-match,omitempty" yaml:"stop-at-first-match,omitempty"`

	IterateAll        bool                 `yaml:"iterate-all,omitempty" json:"iterate-all,omitempty"`
	generator         *protocols.Generator `json:"-" yaml:"-" jsonschema:"-"`
	httpClient        *http.Client         `json:"-" yaml:"-" jsonschema:"-"`
	httpresp          *http.Response       `json:"-" yaml:"-" jsonschema:"-"`
	CompiledOperators *operators.Operators `json:"-" yaml:"-" jsonschema:"-"`
	attackType        protocols.Type       `json:"-" yaml:"-" jsonschema:"-"`
	totalRequests     int                  `json:"-" yaml:"-" jsonschema:"-"`

	options *protocols.ExecuterOptions `json:"-" yaml:"-" jsonschema:"-"`
	//Result            *protocols.Result
}

// Type returns the type of the protocol request
func (r *Request) Type() protocols.ProtocolType {
	return protocols.HTTPProtocol
}

// Match matches a generic data response again a given matcher
func (r *Request) Match(data map[string]interface{}, matcher *operators.Matcher) (bool, []operators.MatchHit) {
	switch matcher.GetType() {
	case operators.StatusMatcher:
		statusCode, ok := data["status_code"]
		if !ok {
			return false, nil
		}
		status, ok := statusCode.(int)
		if !ok {
			return false, nil
		}
		return matcher.Result(matcher.MatchStatusCode(status)), []operators.MatchHit{{Value: common.ToString(statusCode)}}
	case operators.FaviconMatcher:
		item, ok := r.getMatchPart(matcher.Part, data)
		if !ok {
			return false, nil
		}
		return matcher.ResultWithMatchedSnippet(matcher.MatchHashValues(strings.Fields(item)))
	default:
		return protocols.MakeDefaultMatchFunc(data, matcher, func(part string) (string, bool) {
			return r.getMatchPart(part, data)
		})
	}
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, extractor *operators.Extractor) map[string]struct{} {
	item, ok := r.getMatchPart(extractor.Part, data)
	if !ok {
		return nil
	}
	switch extractor.GetType() {
	case operators.RegexExtractor:
		return extractor.ExtractRegex(item)
	case operators.KValExtractor:
		return extractor.ExtractKval(data)
	case operators.DSLExtractor:
		return extractor.ExtractDSL(data)
	default:
		return extractor.ExtractWithHandler(item, data)
	}
}

// getMatchPart returns the match part honoring "all" matchers + others.
func (r *Request) getMatchPart(part string, data protocols.InternalEvent) (string, bool) {
	if part == "" {
		part = "body"
	}
	if part == "header" {
		part = "all_headers"
	}
	var itemStr string

	if part == "all" {
		builder := &strings.Builder{}
		builder.WriteString(common.ToString(data["body"]))
		builder.WriteString(common.ToString(data["all_headers"]))
		itemStr = builder.String()
	} else {
		item, ok := data[part]
		if !ok {
			return "", false
		}
		itemStr = common.ToString(item)
	}
	return itemStr, true
}

func (r *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{r.CompiledOperators}
}

// var (
//
//	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
//
// )
// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 && !wrapped.OperatorsResult.Matched {
		return nil
	}

	matchNames := wrapped.OperatorsResult.MatchesByName()
	extractNames := wrapped.OperatorsResult.ExtractsByName()
	results := make([]*protocols.ResultEvent, 0, len(matchNames)+1)

	if len(matchNames) > 0 {
		for name := range matchNames {
			data := r.MakeResultEventItem(wrapped)
			data.MatcherName = name
			results = append(results, data)
		}
	} else if len(extractNames) > 0 {
		for name, vals := range extractNames {
			data := r.MakeResultEventItem(wrapped)
			data.ExtractorName = name
			data.ExtractedResults = vals
			results = append(results, data)
		}
	} else {
		data := r.MakeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}

func (r *Request) MakeResultEventItem(wrapped *protocols.InternalWrappedEvent) *protocols.ResultEvent {
	data := &protocols.ResultEvent{
		TemplateID: common.ToString(wrapped.InternalEvent["template-id"]),
		//Info:             wrapped.InternalEvent["template-info"].(map[string]interface{}),
		Type:             "http",
		Host:             common.ToString(wrapped.InternalEvent["host"]),
		Matched:          common.ToString(wrapped.InternalEvent["matched"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts(),
		Timestamp:        time.Now(),
		IP:               common.ToString(wrapped.InternalEvent["ip"]),
		Request:          common.ToString(wrapped.InternalEvent["request"]),
		Response:         common.ToString(wrapped.InternalEvent["response"]),
	}
	return data
}

// requests returns the total number of requests the YAML rule will perform
func (r *Request) Requests() int {
	sequenceCount := len(r.Path)
	if len(r.Raw) > 0 {
		sequenceCount = len(r.Raw)
	}
	if r.generator != nil {
		return r.generator.NewIterator().Total() * sequenceCount
	}
	return sequenceCount
}

func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options

	policy := DontFollowRedirect
	if r.Redirects {
		policy = FollowAllRedirect
	} else if r.HostRedirects {
		policy = FollowSameHostRedirect
	}
	connectionConfiguration := &Configuration{
		Timeout:        options.Options.Timeout,
		MaxRedirects:   r.MaxRedirects,
		RedirectPolicy: policy,
		CookieReuse:    r.CookieReuse,
		DisableCookie:  r.DisableCookie,
		DialContext:    options.Options.DialContext,
		Proxy:          options.Options.Proxy,
	}
	r.httpClient = createClient(connectionConfiguration)

	if r.Body != "" && !strings.Contains(r.Body, "\r\n") {
		r.Body = strings.Replace(r.Body, "\n", "\r\n", -1)
	}
	if len(r.Raw) > 0 {
		for i, raw := range r.Raw {
			if !strings.Contains(raw, "\r\n") {
				r.Raw[i] = strings.Replace(raw, "\n", "\r\n", -1)
			}
		}
	}

	// 修改: 只编译一次Matcher
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if compileErr := compiled.Compile(); compileErr != nil {
			return compileErr
		}
		r.CompiledOperators = compiled
	}

	if len(r.Payloads) > 0 {
		var attackType string
		if r.options.Options.AttackType != "" {
			attackType = r.options.Options.AttackType
		} else if len(r.options.Options.VarsPayload) > 0 {
			attackType = "clusterbomb"
		} else if r.AttackType != "" {
			attackType = r.AttackType
		} else {
			attackType = "pitchfork"
		}

		r.attackType = protocols.StringToType[attackType]
		// 允许使用命令行定义对应的参数, 会替换对应的参数, 如果参数的数量对不上可能会报错
		for k, v := range r.options.Options.VarsPayload {
			if _, ok := r.Payloads[k]; ok {
				r.Payloads[k] = v
			}
		}
		for k, payload := range r.Payloads {
			switch payload.(type) {
			case []string:
				tmp := make([]string, len(payload.([]string)))
				for i, p := range payload.([]string) {
					tmp[i] = common.ToString(p)
				}
				r.Payloads[k] = tmp
			}
		}

		var err error
		r.generator, err = protocols.NewGenerator(r.Payloads, r.attackType)
		if err != nil {
			return err
		}
	}
	r.totalRequests = r.Requests()
	return nil
}

func (r *Request) ExecuteWithResults(input *protocols.ScanContext, dynamicValues, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	var err error

	err = r.ExecuteRequestWithResults(input, dynamicValues, previous, callback)
	if err != nil {
		return err
	}
	return nil
}

func (r *Request) ExecuteRequestWithResults(input *protocols.ScanContext, dynamicValues, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	if previous == nil {
		previous = make(map[string]interface{})
	}
	generator := r.newGenerator(input)
	requestCount := 1
	var requestErr error
	var gotDynamicValues map[string]interface{}
	for {
		// returns two values, error and skip, which skips the execution for the request instance.
		executeFunc := func(data string, payloads, dynamicValue map[string]interface{}) (bool, error) {
			generatedHttpRequest, err := generator.Make(input.Input, data, payloads, dynamicValue)
			if err != nil {
				if err == io.EOF || err == errStopExecution {
					return true, nil
				}

				return true, err
			}
			if generatedHttpRequest.request.Header.Get("User-Agent") == "" {
				generatedHttpRequest.request.Header.Set("User-Agent", ua)
			}
			var gotMatches bool
			err = r.executeRequest(input, generatedHttpRequest, previous, func(event *protocols.InternalWrappedEvent) {
				// Add the extracts to the dynamic values if any.
				if event.OperatorsResult != nil {
					gotMatches = event.OperatorsResult.Matched
					if gotDynamicValues == nil {
						gotDynamicValues = make(map[string]interface{})
					}
					for k, v := range event.OperatorsResult.DynamicValues {
						gotDynamicValues[k] = v
					}
				}
				callback(event)
			}, requestCount)

			// If a variable is unresolved, skip all further requests
			if err == errStopExecution {
				return true, nil
			}
			if err != nil {
				requestErr = err
			}
			requestCount++
			//request.options.Progress.IncrementRequests()

			// If this was a match, and we want to stop at first match, skip all further requests.
			if r.StopAtFirstMatch && gotMatches {
				return true, nil
			}
			return false, nil
		}

		inputData, payloads, ok := generator.nextValue()
		if !ok {
			break
		}
		if len(payloads) > 0 {
			common.Debug("payloads: %s", common.MapToString(payloads))
		}
		var gotErr error
		var skip bool

		if len(gotDynamicValues) > 0 {
			operators.MakeDynamicValuesCallback(gotDynamicValues, r.IterateAll, func(data map[string]interface{}) bool {
				// Merge extracted dynamic values with original template variables
				// to preserve user-defined variables (e.g. rand_str) across requests
				mergedValues := common.MergeMaps(dynamicValues, data)
				if skip, gotErr = executeFunc(inputData, payloads, mergedValues); skip || gotErr != nil {
					return true
				}
				return false
			})
		} else {
			skip, gotErr = executeFunc(inputData, payloads, dynamicValues)
		}
		if gotErr != nil && requestErr == nil {
			requestErr = gotErr
		}
		if skip || gotErr != nil {
			break
		}
	}
	return requestErr
}

func (r *Request) executeRequest(input *protocols.ScanContext, request *generatedRequest, previousEvent map[string]interface{}, callback protocols.OutputEventCallback, reqcount int) error {
	var reqBody []byte
	if request.request.Body != nil {
		reqBody, _ = ioutil.ReadAll(request.request.Body)
		request.request.Body = NopCloser(bytes.NewReader(reqBody))
	}

	timeStart := time.Now()
	client := r.clientForExecution(input)
	resp, err := client.Do(request.request)
	common.Debug("request %s %v %v", request.request.Method, request.request.URL, request.dynamicValues)
	common.Dump(request.request)
	if err != nil {
		common.Debug("%s nuclei request failed, %s", request.request.URL, err.Error())
		return err
	}
	duration := time.Since(timeStart)
	matchedURL := input.Input
	if request.request != nil {
		matchedURL = request.request.URL.String()
	}
	// Give precedence to the final URL from response
	if resp.Request != nil {
		if responseURL := resp.Request.URL.String(); responseURL != "" {
			matchedURL = responseURL
		}
	}
	finalEvent := make(map[string]interface{})
	outputEvent := r.responseToDSLMap(request.request, resp, input.Input, matchedURL, duration, request.dynamicValues, reqBody)
	for k, v := range previousEvent {
		finalEvent[k] = v
	}
	for k, v := range outputEvent {
		finalEvent[k] = v
	}

	// Add to history the current request number metadata if asked by the user.
	if r.NeedsRequestCondition() {
		requestIndex := reqcount
		switch offset := request.dynamicValues["__request_index_offset"].(type) {
		case int:
			requestIndex += offset
		case int64:
			requestIndex += int(offset)
		case float64:
			requestIndex += int(offset)
		}
		for k, v := range outputEvent {
			key := fmt.Sprintf("%s_%d", k, requestIndex)
			previousEvent[key] = v
			finalEvent[key] = v
		}
	}
	finalEvent = common.MergeMaps(finalEvent, request.Vars())
	common.Dump(finalEvent)

	event := &protocols.InternalWrappedEvent{InternalEvent: finalEvent}
	if r.CompiledOperators != nil {
		var ok bool
		event.OperatorsResult, ok = r.CompiledOperators.Execute(finalEvent, r.Match, r.Extract)
		if ok && event.OperatorsResult != nil {
			if r.InternalMatchers {
				event.OperatorsResult.Matched = false
				event.Results = nil
			} else {
				event.OperatorsResult.PayloadValues = request.dynamicValues
				event.OperatorsResult.Request = common.ToString(finalEvent["request"])
				event.OperatorsResult.Response = common.ToString(finalEvent["response"])
				event.Results = r.MakeResultEvent(event)
			}
			callback(event)
			return nil
		}
	}
	if input.TraceAll {
		callback(event)
	}
	return err
}

func (r *Request) clientForExecution(input *protocols.ScanContext) *http.Client {
	if r == nil {
		return nil
	}

	client := r.httpClient
	if input == nil {
		return client
	}

	switch {
	case input.Transport != nil && r.httpClient != nil:
		c := *r.httpClient
		c.Transport = input.Transport
		client = &c
	case input.Transport != nil:
		client = &http.Client{Transport: input.Transport}
	case input.Client != nil:
		return input.Client
	}

	if client == nil {
		return nil
	}

	if !r.DisableCookie && input.CookieJar != nil {
		return cloneClientWithJar(client, input.CookieJar)
	}

	return client
}

func cloneClientWithJar(client *http.Client, jar http.CookieJar) *http.Client {
	if client == nil || jar == nil {
		return client
	}
	c := *client
	c.Jar = jar
	return &c
}

// responseToDSLMap converts an HTTP response to a map for use in DSL matching
func (r *Request) responseToDSLMap(req *http.Request, resp *http.Response, host, matched string, duration time.Duration, extra map[string]interface{}, reqBody []byte) protocols.InternalEvent {
	data := make(protocols.InternalEvent, 12+len(extra)+len(resp.Header)+len(resp.Cookies()))
	for k, v := range extra {
		data[k] = v
	}
	for _, cookie := range resp.Cookies() {
		data[strings.ToLower(cookie.Name)] = cookie.Value
	}
	data["host"] = host
	data["type"] = r.Type().String()
	data["matched"] = matched
	data["status_code"] = resp.StatusCode
	data["duration"] = duration.Seconds()
	data["latency"] = float64(duration / time.Millisecond)

	var headerBuilder strings.Builder
	var normalizedHeaderBuilder strings.Builder
	for k, v := range resp.Header {
		joinedValue := strings.Join(v, ", ")
		headerBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", k, joinedValue))
		normalizedKey := strings.ToLower(strings.Replace(strings.TrimSpace(k), "-", "_", -1))
		data[normalizedKey] = strings.Join(v, " ")
		normalizedHeaderBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", normalizedKey, joinedValue))
	}
	data["header"] = headerBuilder.String()
	// all_headers holds the normalized header block (lowercase, "_" for "-").
	// The xray converter emits header existence checks as normalized needles
	// (e.g. contains(all_headers, "content_type:")) because HTTP header names
	// are case-insensitive and the runtime case is unknown; matching against the
	// raw block would miss. data["header"] keeps the original-case raw block.
	data["all_headers"] = normalizedHeaderBuilder.String()

	body, _ := readResponseBody(resp)
	bodyText := string(body)
	data["body"] = bodyText
	if len(body) > 0 {
		data["favicon_hash"] = encode.Mmh3Hash32(body) + " " + encode.Md5Hash(body)
	}
	data["title"] = extractHTMLTitle(bodyText)
	addTLSCertFields(data, resp)
	if strings.TrimSpace(resp.Header.Get("Content-Encoding")) != "" {
		data["content_length"] = len(body)
	} else if resp.ContentLength > -1 {
		data["content_length"] = resp.ContentLength
	} else {
		data["content_length"] = len(body)
	}

	var respRaw bytes.Buffer
	respRaw.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	for k, v := range resp.Header {
		respRaw.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
	}
	respRaw.WriteString("\r\n")
	respRaw.Write(body)
	data["response"] = respRaw.String()
	data["raw"] = data["response"]

	var reqRaw bytes.Buffer
	reqRaw.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.URL.String()))
	for k, v := range req.Header {
		reqRaw.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
	}
	reqRaw.WriteString("\r\n")
	if len(reqBody) > 0 {
		reqRaw.Write(reqBody)
	}
	data["request"] = reqRaw.String()

	if r.StopAtFirstMatch {
		data["stop-at-first-match"] = true
	}
	return data
}

func (r *Request) GetID() string {
	return r.ID
}

func (r *Request) Context() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.options.Options.Timeout)*time.Second)
	go func() { <-ctx.Done(); cancel() }()
	return ctx
}

// SetHTTPClient sets a custom HTTP client for this request
// This allows external callers to provide their own http.Client or http.RoundTripper
func (r *Request) SetHTTPClient(client *http.Client) {
	r.httpClient = client
}

// GetHTTPClient returns the current HTTP client
func (r *Request) GetHTTPClient() *http.Client {
	return r.httpClient
}

var (
	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
)

var (
	// Determines if request condition are needed by detecting the pattern _xxx
	reRequestCondition = regexp.MustCompile(`(?m)_\d+`)
)

// NeedsRequestCondition determines if request condition should be enabled
func (request *Request) NeedsRequestCondition() bool {
	if request.ReqCondition {
		return true
	}
	for _, matcher := range request.Matchers {
		if checkRequestConditionExpressions(matcher.DSL...) {
			return true
		}
		if checkRequestConditionExpressions(matcher.Part) {
			return true
		}
	}
	for _, extractor := range request.Extractors {
		if checkRequestConditionExpressions(extractor.DSL...) {
			return true
		}
		if checkRequestConditionExpressions(extractor.Part) {
			return true
		}
	}

	return false
}

// cloneHeader 复制一份 http.Header（http.Header.Clone 是 go1.13 API，
// 这里手写以保持 go1.11 兼容）。
func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	c := make(http.Header, len(h))
	for k, v := range h {
		c[k] = append([]string(nil), v...)
	}
	return c
}

func extractHTMLTitle(body string) string {
	match := titleRE.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(match[1]))
}

func checkRequestConditionExpressions(expressions ...string) bool {
	for _, expression := range expressions {
		if reRequestCondition.MatchString(expression) {
			return true
		}
	}
	return false
}

var (
	titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// generatedRequest is a single wrapped generated request for a template request
type generatedRequest struct {
	original *Request
	//rawRequest      *raw.Request
	meta map[string]interface{}
	//pipelinedClient *rawhttp.PipelineClient
	request       *http.Request
	dynamicValues map[string]interface{}
}

func (gr *generatedRequest) Vars() map[string]interface{} {
	return common.MergeMaps(gr.meta, gr.dynamicValues)
}

