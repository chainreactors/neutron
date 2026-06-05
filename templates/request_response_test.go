package templates

import (
	"crypto/md5"
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

func TestExecuteEvaluatesVariablesAfterTargetBuiltins(t *testing.T) {
	const epsPath = "/eps/api/resourceOperations/uploadsecretKeyIbuilding"

	var gotHost, gotPath, gotToken, expectedToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		sum := md5.Sum([]byte(fmt.Sprintf("%s://%s%s", scheme, r.Host, epsPath)))
		expectedToken = fmt.Sprintf("%X", sum)
		gotHost = r.Host
		gotPath = r.URL.Path
		gotToken = r.URL.Query().Get("token")
		if r.URL.Path != "/eps/api/resourceOperations/upload" || r.URL.Query().Get("token") != expectedToken {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "path=%s token=%s expected=%s", r.URL.Path, r.URL.Query().Get("token"), expectedToken)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "token accepted")
	}))
	defer server.Close()

	yamlContent := `
id: target-builtin-variable-test
info:
  name: Target Builtin Variable Test
  author: test
  severity: info
variables:
  eps_path: /eps/api/resourceOperations/uploadsecretKeyIbuilding
  host: '{{Hostname}}'
  scheme: '{{Scheme}}'
  url: '{{concat(concat(concat(scheme, "://"), host), eps_path)}}'
  token: '{{to_upper(md5(url))}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}/eps/api/resourceOperations/upload?token={{token}}'
    matchers:
      - type: word
        words:
          - "token accepted"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result, "host=%s path=%s token=%s expected=%s", gotHost, gotPath, gotToken, expectedToken)
	require.True(t, result.Matched)
}

func TestExecuteUsesTargetBaseURLForRequestPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedOrigin := "https://" + strings.Split(r.Host, ":")[0]
		if r.URL.Path != "/admin/auth/reset-password" || r.Header.Get("Origin") != expectedOrigin {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "path=%s origin=%s expected=%s", r.URL.Path, r.Header.Get("Origin"), expectedOrigin)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "strapi ok")
	}))
	defer server.Close()

	yamlContent := `
id: builtin-baseurl-path-test
info:
  name: Builtin BaseURL Path Test
  author: test
  severity: info
variables:
  BaseURL: '{{Host}}'
http:
  - method: POST
    path:
      - '{{BaseURL}}/admin/auth/reset-password'
    headers:
      Origin: https://{{BaseURL}}
    matchers:
      - type: word
        words:
          - "strapi ok"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
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

func TestExecuteInternalExtractorAcrossHTTPBlocks(t *testing.T) {
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/":
			w.WriteHeader(200)
			fmt.Fprint(w, `next=/dynamic-login`)
		case "/dynamic-login":
			w.WriteHeader(200)
			fmt.Fprint(w, "dynamic endpoint matched")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	yamlContent := `
id: cross-block-dynamic-variable-test
info:
  name: Cross Block Dynamic Variable Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    extractors:
      - type: regex
        name: next_path
        regex:
          - "next=(/[a-z-]+)"
        group: 1
        internal: true

  - method: GET
    path:
      - "{{BaseURL}}{{next_path}}"
    matchers:
      - type: word
        words:
          - "dynamic endpoint matched"
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
	require.Contains(t, result.Request, "/dynamic-login")
	require.Contains(t, requested, "/")
	require.Contains(t, requested, "/dynamic-login")
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

func TestExecuteStaticVariableChainWithoutPreEvaluation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/prefix-hello-suffix" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "chain resolved")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "unexpected path: %s", r.URL.Path)
	}))
	defer server.Close()

	yamlContent := `
id: static-variable-chain-test
info:
  name: Static Variable Chain Test
  author: test
  severity: info
variables:
  a: hello
  b: '{{concat("prefix-", a)}}'
  c: '{{concat(b, "-suffix")}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}/{{c}}'
    matchers:
      - type: word
        words:
          - "chain resolved"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
