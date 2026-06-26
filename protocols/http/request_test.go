package http

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestResponseToDSLMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "hello")
		w.WriteHeader(200)
		fmt.Fprint(w, "test body")
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/path", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "test-agent")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	r := &Request{}
	event := r.responseToDSLMap(req, resp, server.URL, server.URL+"/path", 100*time.Millisecond, nil, nil)

	require.Equal(t, 200, event["status_code"])
	require.Equal(t, "test body", event["body"])
	require.Equal(t, server.URL, event["host"])
	require.Equal(t, "http", event["type"])

	// Verify response string contains status line, headers, and body
	respStr := common.ToString(event["response"])
	require.Contains(t, respStr, "200")
	require.Contains(t, respStr, "test body")

	// Verify request string contains method and URL
	reqStr := common.ToString(event["request"])
	require.Contains(t, reqStr, "GET")
	require.Contains(t, reqStr, "/path")
	require.Contains(t, reqStr, "HTTP/1.1")
}

func TestResponseToDSLMapAllHeadersIncludesRawAndNormalizedHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Jenkins", "2.440")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	event := (&Request{}).responseToDSLMap(req, resp, server.URL, server.URL+"/", time.Millisecond, nil, nil)

	require.Contains(t, event["header"], "X-Jenkins: 2.440")
	require.Contains(t, event["all_headers"], "x_jenkins: 2.440")
	require.Contains(t, event["all_headers"], "content_type: application/json")
	require.Equal(t, "2.440", event["x_jenkins"])
	require.Equal(t, "application/json", event["content_type"])
}

func TestResponseToDSLMapDoesNotExposeFaviconRuntimeFields(t *testing.T) {
	var fetchedIcon bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/app/index.html", http.StatusFound)
		case "/app/index.html":
			fmt.Fprint(w, `<html><head><link rel=icon href=static/favicon.ico></head></html>`)
		case "/app/static/favicon.ico":
			fetchedIcon = true
			_, _ = w.Write([]byte("redirected-icon"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	require.NoError(t, err)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)

	request := &Request{
		options: &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}},
	}
	event := request.responseToDSLMap(req, resp, server.URL, server.URL+"/app/index.html", 100*time.Millisecond, nil, nil)

	require.NotContains(t, event, "favicon")
	require.NotContains(t, event, "favicon_content")
	require.Contains(t, event, "favicon_hash")
	require.NotEmpty(t, event["favicon_hash"])
	require.False(t, fetchedIcon)
}

func TestResponseToDSLMapWithRequestBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		fmt.Fprintf(w, "echo: %s", body)
	}))
	defer server.Close()

	reqBody := []byte(`{"key":"value"}`)
	req, err := http.NewRequest("POST", server.URL+"/api", strings.NewReader(string(reqBody)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	r := &Request{}
	event := r.responseToDSLMap(req, resp, server.URL, server.URL+"/api", 100*time.Millisecond, nil, reqBody)

	// Verify request string includes the body
	reqStr := common.ToString(event["request"])
	require.Contains(t, reqStr, "POST")
	require.Contains(t, reqStr, `{"key":"value"}`)
	require.Contains(t, reqStr, "Content-Type: application/json")

	// Verify response string includes echo body
	respStr := common.ToString(event["response"])
	require.Contains(t, respStr, `echo: {"key":"value"}`)
}

func TestExecuteRequestWithRequestResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "matched")
		w.WriteHeader(200)
		fmt.Fprint(w, "target matched content")
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}"},
		Method: "GET",
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"target matched"},
	})

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	err := r.Compile(options)
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL, nil)
	var capturedEvent *protocols.InternalWrappedEvent

	err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.NotNil(t, capturedEvent.OperatorsResult)
	require.True(t, capturedEvent.OperatorsResult.Matched)

	// Verify request/response strings are populated on OperatorsResult
	require.NotEmpty(t, capturedEvent.OperatorsResult.Request)
	require.NotEmpty(t, capturedEvent.OperatorsResult.Response)
	require.Contains(t, capturedEvent.OperatorsResult.Request, "GET")
	require.Contains(t, capturedEvent.OperatorsResult.Request, "HTTP/1.1")
	require.Contains(t, capturedEvent.OperatorsResult.Response, "200")
	require.Contains(t, capturedEvent.OperatorsResult.Response, "target matched content")

	// Verify ResultEvent also has request/response
	require.NotEmpty(t, capturedEvent.Results)
	require.NotEmpty(t, capturedEvent.Results[0].Request)
	require.NotEmpty(t, capturedEvent.Results[0].Response)
}

func TestRedirectsCarrySetCookieWithinRedirectChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "redirect-cookie", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			if cookie, err := r.Cookie("sid"); err == nil && cookie.Value == "redirect-cookie" {
				fmt.Fprint(w, "cookie-carried")
				return
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "missing-cookie")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	r := &Request{
		Path:      []string{"{{BaseURL}}/start"},
		Method:    "GET",
		Redirects: true,
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"cookie-carried"},
	})
	require.NoError(t, r.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	var matched bool
	err := r.ExecuteWithResults(protocols.NewScanContext(server.URL, nil), map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.True(t, matched)
}

func TestPerContextCookieJarSharedWithinExecution(t *testing.T) {
	var checkSawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "redirect-cookie", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("ok"))
		case "/check":
			if cookie, err := r.Cookie("sid"); err == nil && cookie.Value == "redirect-cookie" {
				checkSawCookie = true
			}
			_, _ = w.Write([]byte("checked"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	r := &Request{
		Path:      []string{"{{BaseURL}}/start", "{{BaseURL}}/check"},
		Method:    "GET",
		Redirects: true,
	}
	require.NoError(t, r.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	input := protocols.NewScanContext(server.URL, nil)
	input.TraceAll = true
	err := r.ExecuteWithResults(input, map[string]interface{}{}, map[string]interface{}{}, func(*protocols.InternalWrappedEvent) {})
	require.NoError(t, err)
	require.True(t, checkSawCookie, "per-context jar should carry cookies within the same execution")
}

func TestCookieReuseSharesJarWithinExecution(t *testing.T) {
	var checkSawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "reuse-cookie", Path: "/"})
			fmt.Fprint(w, "logged-in")
		case "/check":
			if cookie, err := r.Cookie("sid"); err == nil && cookie.Value == "reuse-cookie" {
				checkSawCookie = true
				fmt.Fprint(w, "cookie-present")
				return
			}
			fmt.Fprint(w, "missing-cookie")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	loginReq := &Request{
		Path:        []string{"{{BaseURL}}/login"},
		Method:      "GET",
		CookieReuse: true,
	}
	require.NoError(t, loginReq.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	checkReq := &Request{
		Path:        []string{"{{BaseURL}}/check"},
		Method:      "GET",
		CookieReuse: true,
	}
	checkReq.Matchers = append(checkReq.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"cookie-present"},
	})
	require.NoError(t, checkReq.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	ctx := protocols.NewScanContext(server.URL, nil)
	err := loginReq.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(*protocols.InternalWrappedEvent) {})
	require.NoError(t, err)

	var matched bool
	err = checkReq.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.True(t, checkSawCookie)
	require.True(t, matched)

	checkSawCookie = false
	matched = false
	err = checkReq.ExecuteWithResults(protocols.NewScanContext(server.URL, nil), map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.False(t, checkSawCookie, "cookies must not leak across separate scan contexts")
	require.False(t, matched)
}

func TestCookieJarIsSharedAcrossRequestBlocksByDefault(t *testing.T) {
	var checkSawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/whoAmI/":
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "from-server", Path: "/"})
			w.Header().Set("X-Jenkins", "2.440")
			if _, err := r.Cookie("JSESSIONID"); err == nil {
				checkSawCookie = true
				fmt.Fprint(w, "Cookie JSESSIONID SessionId: null")
				return
			}
			fmt.Fprint(w, "SessionId: null")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	firstReq := &Request{
		Path:   []string{"{{BaseURL}}/whoAmI/"},
		Method: "GET",
	}
	require.NoError(t, firstReq.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	secondReq := &Request{
		Path:   []string{"{{BaseURL}}/whoAmI/"},
		Method: "GET",
	}
	secondReq.Matchers = append(secondReq.Matchers, &operators.Matcher{
		Type: "dsl",
		DSL:  []string{`status_code == 200 && contains(all_headers, "x_jenkins:") && contains(body, "Cookie") && contains(body, "SessionId: null")`},
	})
	require.NoError(t, secondReq.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	ctx := protocols.NewScanContext(server.URL, nil)
	err := firstReq.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(*protocols.InternalWrappedEvent) {})
	require.NoError(t, err)

	var matched bool
	err = secondReq.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.True(t, checkSawCookie)
	require.True(t, matched)
}

func TestDisableCookiePreventsRawSequenceCookieReplay(t *testing.T) {
	var secondSawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/whoAmI/":
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "from-server", Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("X-Jenkins", "2.440")
			if _, err := r.Cookie("JSESSIONID"); err == nil {
				secondSawCookie = true
				fmt.Fprint(w, "Cookie JSESSIONID SessionId: null")
				return
			}
			fmt.Fprint(w, "SessionId: null")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	r := &Request{
		Raw: []string{
			"GET /whoAmI/ HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
			"GET /whoAmI/ HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
		},
		DisableCookie: true,
		Operators:     operators.Operators{MatchersCondition: "and"},
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:      "word",
		Part:      "header",
		Words:     []string{"text/html", "x-jenkins"},
		Condition: "and",
	})
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:      "word",
		Part:      "body_2",
		Words:     []string{"Cookie", "SessionId: null"},
		Condition: "and",
	})
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:   "status",
		Status: []int{200},
	})
	require.NoError(t, r.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	var matched bool
	err := r.ExecuteWithResults(protocols.NewScanContext(server.URL, nil), map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.False(t, secondSawCookie)
	require.False(t, matched)
}

func TestDisableCookiePreventsSharingAcrossRequestBlocks(t *testing.T) {
	var checkSawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "disabled-cookie", Path: "/"})
			fmt.Fprint(w, "logged-in")
		case "/check":
			if cookie, err := r.Cookie("sid"); err == nil && cookie.Value == "disabled-cookie" {
				checkSawCookie = true
				fmt.Fprint(w, "cookie-present")
				return
			}
			fmt.Fprint(w, "missing-cookie")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	loginReq := &Request{
		Path:          []string{"{{BaseURL}}/login"},
		Method:        "GET",
		DisableCookie: true,
	}
	require.NoError(t, loginReq.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	checkReq := &Request{
		Path:          []string{"{{BaseURL}}/check"},
		Method:        "GET",
		DisableCookie: true,
	}
	checkReq.Matchers = append(checkReq.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"cookie-present"},
	})
	require.NoError(t, checkReq.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	ctx := protocols.NewScanContext(server.URL, nil)
	err := loginReq.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(*protocols.InternalWrappedEvent) {})
	require.NoError(t, err)

	var matched bool
	err = checkReq.ExecuteWithResults(ctx, map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.False(t, checkSawCookie)
	require.False(t, matched)
}

func TestPerContextCookieJarIsolatedAcrossExecutions(t *testing.T) {
	var secondSawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "exec-cookie", Path: "/"})
			fmt.Fprint(w, "logged-in")
		case "/check":
			if cookie, err := r.Cookie("sid"); err == nil && cookie.Value == "exec-cookie" {
				secondSawCookie = true
			}
			fmt.Fprint(w, "checked")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}/login"},
		Method: "GET",
	}
	require.NoError(t, r.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	ctx1 := protocols.NewScanContext(server.URL, nil)
	err := r.ExecuteWithResults(ctx1, map[string]interface{}{}, map[string]interface{}{}, func(*protocols.InternalWrappedEvent) {})
	require.NoError(t, err)

	r2 := &Request{
		Path:   []string{"{{BaseURL}}/check"},
		Method: "GET",
	}
	require.NoError(t, r2.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}))

	ctx2 := protocols.NewScanContext(server.URL, nil)
	err = r2.ExecuteWithResults(ctx2, map[string]interface{}{}, map[string]interface{}{}, func(*protocols.InternalWrappedEvent) {})
	require.NoError(t, err)
	require.False(t, secondSawCookie, "cookies must not leak across separate scan contexts")
}

func TestExecuteSkipsUnresolvedDynamicPath(t *testing.T) {
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.EscapedPath())
		w.WriteHeader(200)
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{`{{BaseURL}}/{{trim_prefix(urlpath, "/")}}/`},
		Method: "GET",
	}

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	err := r.Compile(options)
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL, nil)
	err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		t.Fatalf("unresolved dynamic path should not emit events: %#v", event)
	})
	require.NoError(t, err)
	require.Empty(t, requested)
}

func TestExecuteKeepsLiteralDoubleBracePayload(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(200)
		fmt.Fprint(w, receivedBody)
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}"},
		Method: "POST",
		Body:   "{{7*7}}",
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"{{7*7}}"},
	})

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	require.NoError(t, r.Compile(options))

	input := protocols.NewScanContext(server.URL, nil)
	var matched bool
	err := r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		if event.OperatorsResult != nil {
			matched = event.OperatorsResult.Matched
		}
	})
	require.NoError(t, err)
	require.Equal(t, "{{7*7}}", receivedBody)
	require.True(t, matched)
}

func TestExecuteRequestWithPOSTBody(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	r := &Request{
		Raw: []string{"POST /submit HTTP/1.1\r\nHost: {{Hostname}}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=test"},
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"ok"},
	})

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	err := r.Compile(options)
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL, nil)
	var capturedEvent *protocols.InternalWrappedEvent

	err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)

	// Verify the server received the body
	require.Equal(t, "user=admin&pass=test", receivedBody)

	// Verify the captured request string includes the body
	require.Contains(t, capturedEvent.OperatorsResult.Request, "user=admin&pass=test")
}

func TestTemplateVariableOverridesGlobalRandstrInRequestBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := ioutil.ReadAll(r.Body)
		fmt.Fprint(w, string(body))
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}"},
		Method: "POST",
		Body:   "{{randstr}}",
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type: "dsl",
		DSL:  []string{"contains(body, randstr)"},
	})

	var variables protocols.Variable
	require.NoError(t, yaml.Unmarshal([]byte("randstr: template-randstr"), &variables))

	options := &protocols.ExecuterOptions{
		Variables: variables,
		Options:   &protocols.Options{Timeout: 5},
	}
	require.NoError(t, r.Compile(options))

	input := protocols.NewScanContext(server.URL, nil)
	var capturedEvent *protocols.InternalWrappedEvent
	err := r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.NotNil(t, capturedEvent.OperatorsResult)
	require.True(t, capturedEvent.OperatorsResult.Matched)
	require.Contains(t, capturedEvent.OperatorsResult.Request, "template-randstr")
	require.Contains(t, capturedEvent.OperatorsResult.Response, "template-randstr")
}

func TestPayloadPathRequestsUseSequentialRequestConditionIndexes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "payload=%s", strings.TrimPrefix(r.URL.Path, "/"))
	}))
	defer server.Close()

	r := &Request{
		Path:     []string{"{{BaseURL}}/{{p}}"},
		Method:   "GET",
		Payloads: map[string]interface{}{"p": []string{"one", "two"}},
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type: "dsl",
		DSL:  []string{`contains(body_1, "payload=one") && contains(body_2, "payload=two")`},
	})

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	require.NoError(t, r.Compile(options))
	require.Equal(t, 2, r.Requests())

	for _, payloads := range []map[string]interface{}{nil, {}} {
		input := protocols.NewScanContext(server.URL, payloads)
		var matched bool
		err := r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
			if event.OperatorsResult != nil {
				matched = event.OperatorsResult.Matched
			}
		})
		require.NoError(t, err)
		require.True(t, matched)
	}
}

func TestMatcherTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Server", "neutron-test")
		w.WriteHeader(403)
		fmt.Fprint(w, "forbidden access")
	}))
	defer server.Close()

	t.Run("status matcher", func(t *testing.T) {
		r := &Request{
			Path:   []string{"{{BaseURL}}"},
			Method: "GET",
		}
		r.Matchers = append(r.Matchers, &operators.Matcher{
			Type:   "status",
			Status: []int{403},
		})

		options := &protocols.ExecuterOptions{
			Options: &protocols.Options{Timeout: 5},
		}
		err := r.Compile(options)
		require.NoError(t, err)

		input := protocols.NewScanContext(server.URL, nil)
		var matched bool
		err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
			if event.OperatorsResult != nil {
				matched = event.OperatorsResult.Matched
			}
		})
		require.NoError(t, err)
		require.True(t, matched)
	})

	t.Run("regex matcher", func(t *testing.T) {
		r := &Request{
			Path:   []string{"{{BaseURL}}"},
			Method: "GET",
		}
		r.Matchers = append(r.Matchers, &operators.Matcher{
			Type:  "regex",
			Regex: []string{`forbidden\s+access`},
		})

		options := &protocols.ExecuterOptions{
			Options: &protocols.Options{Timeout: 5},
		}
		err := r.Compile(options)
		require.NoError(t, err)

		input := protocols.NewScanContext(server.URL, nil)
		var matched bool
		err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
			if event.OperatorsResult != nil {
				matched = event.OperatorsResult.Matched
			}
		})
		require.NoError(t, err)
		require.True(t, matched)
	})
}

func TestExtractorInHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Version", "2.5.1")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"version":"3.1.0","name":"neutron"}`)
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}"},
		Method: "GET",
	}
	r.Extractors = append(r.Extractors, &operators.Extractor{
		Type:  "regex",
		Regex: []string{`"version":"([^"]+)"`},
		Name:  "app_version",
	})

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	err := r.Compile(options)
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL, nil)
	var capturedResult *protocols.InternalWrappedEvent

	err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		capturedResult = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedResult)
	require.NotNil(t, capturedResult.OperatorsResult)
	require.True(t, capturedResult.OperatorsResult.Extracted)
	require.Contains(t, capturedResult.OperatorsResult.Extracts, "app_version")
}

func TestNoMatchNoRequestResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "normal page")
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}"},
		Method: "GET",
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"this-will-not-match"},
	})

	options := &protocols.ExecuterOptions{
		Options: &protocols.Options{Timeout: 5},
	}
	err := r.Compile(options)
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL, nil)
	var called bool
	err = r.ExecuteWithResults(input, make(map[string]interface{}), make(map[string]interface{}), func(event *protocols.InternalWrappedEvent) {
		called = true
	})
	require.NoError(t, err)
	require.False(t, called, "callback should not be called when no match")
}
