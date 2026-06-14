package http

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	event := r.responseToDSLMap(req, resp, server.URL, server.URL+"/path", 100*time.Millisecond, nil, nil, nil)

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

func TestFetchFaviconUsesFreshRequestContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/favicon.ico" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("icon"))
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req = req.WithContext(ctx)

	request := &Request{
		options: &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}},
	}
	body, ok := request.fetchFavicon(req, server.URL+"/favicon.ico", server.Client())
	require.True(t, ok)
	require.Equal(t, []byte("icon"), body)
}

func TestDiscoverIconURLsSupportsUnquotedAttrs(t *testing.T) {
	base, err := url.Parse("http://example.test/systemcenter/index.html")
	require.NoError(t, err)

	urls := discoverIconURLs(base, `<html><head><link rel=icon href=/systemcenter/static/favicon.ico></head></html>`)

	require.Contains(t, urls, "http://example.test/systemcenter/static/favicon.ico")
}

func TestDiscoverIconURLsFallbackIncludesCurrentDirectoryAndRoot(t *testing.T) {
	base, err := url.Parse("http://example.test/portal/")
	require.NoError(t, err)

	urls := discoverIconURLs(base, `<html><head></head><body></body></html>`)

	require.Contains(t, urls, "http://example.test/portal/favicon.ico")
	require.Contains(t, urls, "http://example.test/favicon.ico")
}

func TestDiscoverIconURLsFallbackDedupesRootPath(t *testing.T) {
	base, err := url.Parse("http://example.test/")
	require.NoError(t, err)

	urls := discoverIconURLs(base, `<html><head></head><body></body></html>`)

	require.Equal(t, []string{"http://example.test/favicon.ico"}, urls)
}

func TestResponseToDSLMapUsesFinalRedirectURLForFaviconDiscovery(t *testing.T) {
	iconBody := []byte("redirected-icon")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/app/index.html", http.StatusFound)
		case "/app/index.html":
			fmt.Fprint(w, `<html><head><link rel=icon href=static/favicon.ico></head></html>`)
		case "/app/static/favicon.ico":
			_, _ = w.Write(iconBody)
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
		Operators: operators.Operators{
			Matchers: []*operators.Matcher{{Type: "favicon", Hash: []string{xrayFaviconHash(iconBody)}}},
		},
		options: &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}},
	}
	event := request.responseToDSLMap(req, resp, server.URL, server.URL+"/app/index.html", 100*time.Millisecond, nil, nil, server.Client())

	faviconData, ok := event["favicon"].(map[string]interface{})
	require.True(t, ok)
	require.Contains(t, faviconData, server.URL+"/app/static/favicon.ico")
	require.Contains(t, event["favicon_hash"], xrayFaviconHash(iconBody))
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
	event := r.responseToDSLMap(req, resp, server.URL, server.URL+"/api", 100*time.Millisecond, nil, reqBody, nil)

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

func TestRedirectCookieJarIsIsolatedWhenCookieReuseFalse(t *testing.T) {
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
	require.False(t, checkSawCookie, "redirect cookies must not leak into the next path without cookie-reuse")
}

func TestExecuteRootURLUsesScanContextPathPrefix(t *testing.T) {
	// When the caller sets PathPrefix on the ScanContext, RootURL should expand
	// to scheme://host + prefix (not the literal scan input). Templates that
	// compute paths relative to the app's mount point land where the caller
	// expects, without having to change the template or the scan target.
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/apis/IGI/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "mounted-rooturl-match")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "miss: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{RootURL}}/IGI/"},
		Method: "GET",
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"mounted-rooturl-match"},
	})
	err := r.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}})
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL+"/entry/", nil)
	input.PathPrefix = "/apis/"

	var capturedEvent *protocols.InternalWrappedEvent
	err = r.ExecuteWithResults(input, map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.True(t, capturedEvent.OperatorsResult.Matched)
	require.Contains(t, strings.Join(requested, ","), "/apis/IGI/")
}

func TestExecutePathPrefixDoesNotChangeBaseURL(t *testing.T) {
	// BaseURL must stay the literal scan input even when PathPrefix is set.
	// Templates that use {{BaseURL}} (e.g. the standard nuclei vuln idiom)
	// must keep behaving exactly as before — only RootURL is affected.
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/entry/IGI/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "baseurl-match")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "miss: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	r := &Request{
		Path:   []string{"{{BaseURL}}/IGI/"},
		Method: "GET",
	}
	r.Matchers = append(r.Matchers, &operators.Matcher{
		Type:  "word",
		Words: []string{"baseurl-match"},
	})
	err := r.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}})
	require.NoError(t, err)

	input := protocols.NewScanContext(server.URL+"/entry/", nil)
	input.PathPrefix = "/apis/"

	var capturedEvent *protocols.InternalWrappedEvent
	err = r.ExecuteWithResults(input, map[string]interface{}{}, map[string]interface{}{}, func(event *protocols.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.True(t, capturedEvent.OperatorsResult.Matched)
	require.Contains(t, strings.Join(requested, ","), "/entry/IGI/")
	require.NotContains(t, strings.Join(requested, ","), "/apis/entry/IGI/")
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
