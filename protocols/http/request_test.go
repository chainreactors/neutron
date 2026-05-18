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
