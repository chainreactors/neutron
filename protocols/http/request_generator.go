package http

import (
	"fmt"
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/utils/iutils"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
)

type requestGenerator struct {
	currentIndex    int
	request         *Request
	payloadIterator *protocols.Iterator
	rawRequest      *rawRequest
}

// newGenerator creates a NewGenerator request generator instance
func (r *Request) newGenerator() *requestGenerator {
	generator := &requestGenerator{request: r}
	if len(r.Payloads) > 0 {
		generator.payloadIterator = r.generator.NewIterator()
	}
	return generator
}

// nextValue returns the next path or the next raw request depending on user input
// It returns false if all the inputs have been exhausted by the generator instance.
func (r *requestGenerator) nextValue() (value string, payloads map[string]interface{}, result bool) {
	// If we have paths, return the next path.
	if len(r.request.Path) > 0 && r.currentIndex < len(r.request.Path) {
		if value := r.request.Path[r.currentIndex]; value != "" {
			r.currentIndex++

			if r.payloadIterator != nil {
				payload, ok := r.payloadIterator.Value()
				if !ok {
					r.payloadIterator.Reset()
					// No more payloads request for us now.
					if len(r.request.Path) == r.currentIndex {
						return "", nil, false
					}
					if value != "" {
						newPayload, ok := r.payloadIterator.Value()
						return value, newPayload, ok
					}
					return "", nil, false
				}
				return value, payload, true
			}
			return value, nil, true
		}
	}

	// If we have raw requests, start with the request at current index.
	// If we are not at the start, then check if the iterator for payloads
	// has finished if there are any.
	//
	// If the iterator has finished for the current raw request
	// then reset it and move on to the next value, otherwise use the last request.
	if len(r.request.Raw) > 0 && r.currentIndex < len(r.request.Raw) {
		if r.payloadIterator != nil {
			payload, ok := r.payloadIterator.Value()
			if !ok {
				r.currentIndex++
				r.payloadIterator.Reset()

				// No more payloads request for us now.
				if len(r.request.Raw) == r.currentIndex {
					return "", nil, false
				}
				if item := r.request.Raw[r.currentIndex]; item != "" {
					newPayload, ok := r.payloadIterator.Value()
					return item, newPayload, ok
				}
				return "", nil, false
			}
			return r.request.Raw[r.currentIndex], payload, true
		}
		if item := r.request.Raw[r.currentIndex]; item != "" {
			r.currentIndex++
			return item, nil, true
		}
	}
	return "", nil, false
}

// Total returns the total number of requests for the generator
func (r *requestGenerator) Total() int {
	if r.payloadIterator != nil {
		return len(r.request.Raw) * r.payloadIterator.Remaining()
	}
	return len(r.request.Path)
}

// Make creates a http request for the provided input.
// It returns io.EOF as error when all the requests have been exhausted.
func (r *requestGenerator) Make(baseURL, data string, payloads, dynamicValues map[string]interface{}) (*generatedRequest, error) {
	// We get the next payload for the request.
	var err error
	allVars := iutils.MergeMaps(payloads, dynamicValues)
	for payloadName, payloadValue := range payloads {
		payloads[payloadName], err = common.Evaluate(iutils.ToString(payloadValue), allVars)
		if err != nil {
			return nil, err
		}
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	data, parsed = baseURLWithTemplatePrefs(data, parsed)
	isRawRequest := len(r.request.Raw) > 0

	trailingSlash := false
	if !isRawRequest && strings.HasSuffix(parsed.Path, "/") && strings.Contains(data, "{{BaseURL}}/") {
		trailingSlash = true
	}
	values := iutils.MergeMaps(allVars, generateVariables(parsed, trailingSlash))

	data, err = common.Evaluate(data, values)
	if err != nil {
		return nil, err
	}

	if isRawRequest {
		return r.makeHTTPRequestFromRaw(parsed.String(), data, values)
	}
	return r.makeHTTPRequestFromModel(data, values)
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
func (r *requestGenerator) makeHTTPRequestFromModel(data string, values map[string]interface{}) (*generatedRequest, error) {
	// Build a request on the specified URL
	req, err := http.NewRequest(r.request.Method, data, nil)
	if err != nil {
		return nil, err
	}

	request, err := r.fillRequest(req, values)
	if err != nil {
		return nil, err
	}
	return &generatedRequest{request: request, original: r.request, meta: values}, nil
}

// makeHTTPRequestFromRaw creates a *http.Request from a raw request
func (r *requestGenerator) makeHTTPRequestFromRaw(baseURL, data string, values map[string]interface{}) (*generatedRequest, error) {
	// request values.
	var request *http.Request
	rawRequestData, err := parseRaw(data, baseURL, r.request.Unsafe)
	if err != nil {
		return nil, err
	}

	// Unsafe option uses rawhttp library
	if r.request.Unsafe {
		request = rawRequestData.makeRequest()
		unsafeReq := &generatedRequest{request: request, meta: values, original: r.request}
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
	return &generatedRequest{request: request, meta: values, original: r.request}, nil
}

// fillRequest fills various headers in the request with values
func (r *requestGenerator) fillRequest(req *http.Request, values map[string]interface{}) (*http.Request, error) {
	// Set the header values requested
	var err error
	for i, value := range r.request.Path {
		r.request.Path[i], err = common.Evaluate(value, values)
		if err != nil {
			return nil, common.EvalError
		}
	}
	for header, value := range r.request.Headers {
		value, err := common.Evaluate(value, values)
		if err != nil {
			return nil, common.EvalError
		}
		req.Header[header] = []string{value}
		if header == "Host" {
			req.Host = value
		}
	}

	// In case of multiple threads the underlying connection should remain open to allow reuse
	//if r.request.Threads <= 0 && req.header.Get("Connection") == "" {
	//	req.Close = true
	//}

	// Check if the user requested a request body
	if r.request.Body != "" {
		body, err := common.Evaluate(r.request.Body, values)
		if err != nil {
			return nil, common.EvalError
		}
		req.Body = ioutil.NopCloser(strings.NewReader(body))
	}

	// Only set these headers on non raw requests
	if len(r.request.Raw) == 0 {
		setHeader(req, "Accept", "*/*")
		setHeader(req, "Accept-Language", "en")
	}
	return req, nil
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
func generateVariables(parsed *url.URL, trailingSlash bool) map[string]interface{} {
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
	return map[string]interface{}{
		"BaseURL":  parsed.String(),
		"RootURL":  fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host),
		"Hostname": parsed.Host,
		"Host":     domain,
		"Port":     port,
		"Path":     directory,
		"File":     base,
		"Scheme":   parsed.Scheme,
	}
}
