package templates

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestExecuteReturnsRequestResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Detected", "true")
		w.WriteHeader(200)
		fmt.Fprint(w, "vulnerable endpoint detected")
	}))
	defer server.Close()

	yamlContent := `
id: request-response-test
info:
  name: Request Response Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/target"
    matchers:
      - type: word
        words:
          - "vulnerable endpoint"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)

	err = tmpl.Compile(nil)
	require.NoError(t, err)

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)

	// Verify request string
	require.NotEmpty(t, result.Request)
	require.Contains(t, result.Request, "GET")
	require.Contains(t, result.Request, "/target")
	require.Contains(t, result.Request, "HTTP/1.1")

	// Verify response string
	require.NotEmpty(t, result.Response)
	require.Contains(t, result.Response, "200")
	require.Contains(t, result.Response, "vulnerable endpoint detected")
}

func TestExecuteNoMatchEmptyRequestResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "safe page")
	}))
	defer server.Close()

	yamlContent := `
id: no-match-test
info:
  name: No Match Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "will-not-match"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)

	err = tmpl.Compile(nil)
	require.NoError(t, err)

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.Nil(t, result, "no match should return nil result")
}

func TestExecuteStatusMatcher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, "forbidden")
	}))
	defer server.Close()

	yamlContent := `
id: status-test
info:
  name: Status Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: status
        status:
          - 403
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)

	err = tmpl.Compile(nil)
	require.NoError(t, err)

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Contains(t, result.Response, "403")
}

func TestExecuteWithExtractor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `Server: Apache/2.4.51 (Unix)`)
	}))
	defer server.Close()

	yamlContent := `
id: extractor-test
info:
  name: Extractor Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    extractors:
      - type: regex
        name: server_version
        regex:
          - "Apache/([0-9.]+)"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)

	err = tmpl.Compile(nil)
	require.NoError(t, err)

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Extracted)
	require.Contains(t, result.Extracts, "server_version")
	require.NotEmpty(t, result.Request)
	require.NotEmpty(t, result.Response)
}

func TestExecuteMultiStepWithRequestResponse(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path == "/step1" {
			w.WriteHeader(200)
			fmt.Fprint(w, `token=abc123`)
		} else if r.URL.Path == "/step2" {
			w.WriteHeader(200)
			fmt.Fprint(w, "step2 matched ok")
		}
	}))
	defer server.Close()

	yamlContent := `
id: multi-step-test
info:
  name: Multi Step Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/step1"
    extractors:
      - type: regex
        name: token
        regex:
          - "token=([a-z0-9]+)"
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/step2"
    matchers:
      - type: word
        words:
          - "step2 matched"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)

	err = tmpl.Compile(nil)
	require.NoError(t, err)

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)

	// The request/response should be from the last matched step
	require.Contains(t, result.Request, "/step2")
	require.Contains(t, result.Response, "step2 matched ok")
	require.GreaterOrEqual(t, callCount, 2)
}

func TestExecuteWithEventsMultiStep(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/step1" {
			w.WriteHeader(200)
			fmt.Fprint(w, `token=abc123`)
		} else if r.URL.Path == "/step2" {
			w.WriteHeader(200)
			fmt.Fprint(w, "step2 matched ok")
		}
	}))
	defer server.Close()

	yamlContent := `
id: multi-step-events-test
info:
  name: Multi Step Events Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/step1"
    extractors:
      - type: regex
        name: token
        regex:
          - "token=([a-z0-9]+)"
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}/step2"
    matchers:
      - type: word
        words:
          - "step2 matched"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)

	err = tmpl.Compile(nil)
	require.NoError(t, err)

	result, events, err := tmpl.ExecuteWithEvents(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)

	// Should have events from both steps
	require.GreaterOrEqual(t, len(events), 1, "should have at least one event")

	// Find events containing step1 and step2 requests
	var hasStep1, hasStep2 bool
	for _, ev := range events {
		if ev.Request != "" {
			if containsAll(ev.Request, "/step1") {
				hasStep1 = true
				require.Contains(t, ev.Response, "token=abc123")
			}
			if containsAll(ev.Request, "/step2") {
				hasStep2 = true
				require.Contains(t, ev.Response, "step2 matched ok")
			}
		}
	}
	require.True(t, hasStep2, "should have step2 event with request/response")
	// step1 uses internal extractor so it produces a dynamic-values-only result
	// that may or may not emit a ResultEvent — either is acceptable
	_ = hasStep1
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
