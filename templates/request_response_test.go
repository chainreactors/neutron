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

func TestExecuteKeepsRandomVariablesStableAcrossHTTPBlocks(t *testing.T) {
	var createdUser string
	var requestedUsers []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		requestedUsers = append(requestedUsers, username)
		switch r.URL.Path {
		case "/create":
			createdUser = username
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "created %s", username)
		case "/list":
			if username != "" && username == createdUser {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "found %s", username)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "missing %s created %s", username, createdUser)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: random-variable-stability-test
info:
  name: Random Variable Stability Test
  author: test
  severity: info
variables:
  r1: '{{rand_base(16, "abcdefghijklmnopqrstuvwxyz")}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}/create?username={{r1}}'
    extractors:
      - type: regex
        name: created_user
        regex:
          - "created ([a-z]+)"
        internal: true

  - method: GET
    path:
      - '{{BaseURL}}/list?username={{r1}}'
    matchers:
      - type: word
        words:
          - "found"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Len(t, requestedUsers, 2)
	require.Equal(t, requestedUsers[0], requestedUsers[1])

	firstRunUser := requestedUsers[0]
	result, err = tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Len(t, requestedUsers, 4)
	require.Equal(t, requestedUsers[2], requestedUsers[3])
	require.NotEqual(t, firstRunUser, requestedUsers[2])
}

func TestExecuteKeepsPreprocessorRandstrStableAcrossHTTPBlocks(t *testing.T) {
	var createdToken string
	var createdNamed string
	var requestedTokens []string
	var requestedNamed []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		named := r.URL.Query().Get("named")
		requestedTokens = append(requestedTokens, token)
		requestedNamed = append(requestedNamed, named)
		switch r.URL.Path {
		case "/create":
			createdToken = token
			createdNamed = named
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "created")
		case "/check":
			if token != "" && token == createdToken && named != "" && named == createdNamed {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "found")
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "missing token=%s named=%s", token, named)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: randstr-preprocessor-stability-test
info:
  name: Randstr Preprocessor Stability Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/create?token={{randstr}}&named={{randstr_probe}}'

  - method: GET
    path:
      - '{{BaseURL}}/check?token={{randstr}}&named={{randstr_probe}}'
    matchers:
      - type: word
        words:
          - "found"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Len(t, requestedTokens, 2)
	require.Len(t, requestedNamed, 2)
	require.Equal(t, requestedTokens[0], requestedTokens[1])
	require.Equal(t, requestedNamed[0], requestedNamed[1])
	require.NotEmpty(t, requestedTokens[0])
	require.NotEmpty(t, requestedNamed[0])
}

func TestExecuteKeepsRandomVariableStableWhenLiteralMatchesUnfrozenVariableName(t *testing.T) {
	var createdUser string
	var requestedUsers []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		requestedUsers = append(requestedUsers, username)
		switch r.URL.Path {
		case "/create":
			createdUser = username
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "created %s", username)
		case "/list":
			if username == createdUser {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "found %s", username)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "missing %s created %s", username, createdUser)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: random-literal-dependency-test
info:
  name: Random Literal Dependency Test
  author: test
  severity: info
variables:
  token: '{{Hostname}}'
  r1: '{{concat("token-", rand_base(8, "abc"))}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}/create?username={{r1}}'
    extractors:
      - type: regex
        name: created_user
        regex:
          - "created ([a-z-]+)"
        internal: true

  - method: GET
    path:
      - '{{BaseURL}}/list?username={{r1}}'
    matchers:
      - type: word
        words:
          - "found"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Len(t, requestedUsers, 2)
	require.Equal(t, requestedUsers[0], requestedUsers[1])
}

func TestExecuteDynamicExtractorFeedsNextHTTPBlock(t *testing.T) {
	var requestedToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seed":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "token=real-token")
		case "/check":
			requestedToken = r.URL.Query().Get("token")
			if requestedToken == "real-token" {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "accepted")
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "bad token %s", requestedToken)
		}
	}))
	defer server.Close()

	yamlContent := `
id: dynamic-extractor-cross-block-test
info:
  name: Dynamic Extractor Cross Block Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/seed'
    extractors:
      - type: regex
        name: token
        regex:
          - "token=([a-z-]+)"
        group: 1
        internal: true

  - method: GET
    path:
      - '{{BaseURL}}/check?token={{token}}'
    matchers:
      - type: word
        words:
          - "accepted"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Equal(t, "real-token", requestedToken)
}

func TestExecuteRuntimeDependentVariableFeedsDSLMatcher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/seed":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "seed=abc")
		case "/check":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "accepted-abc")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: runtime-variable-dsl-test
info:
  name: Runtime Variable DSL Test
  author: test
  severity: info
variables:
  token: '{{concat("accepted-", seed)}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}/seed'
    extractors:
      - type: regex
        name: seed
        regex:
          - "seed=([a-z]+)"
        group: 1
        internal: true

  - method: GET
    path:
      - '{{BaseURL}}/check'
    matchers:
      - type: dsl
        dsl:
          - 'contains(body, token)'
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

func TestExecuteFaviconContentDSL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><head><link rel="icon" href="/custom.ico"></head></html>`)
		case "/custom.ico":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ICON-CONTENT-BYTES")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: favicon-content-dsl-test
info:
  name: Favicon Content DSL Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/'
    matchers:
      - type: dsl
        dsl:
          - 'contains(favicon_content, "ICON-CONTENT-BYTES")'
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

func TestExecuteAppendsRequestPathToTargetBaseURLPath(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/es/_count" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "unexpected path: %s", r.URL.Path)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "path preserved")
	}))
	defer server.Close()

	yamlContent := `
id: target-baseurl-path-append-test
info:
  name: Target BaseURL Path Append Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/_count'
    matchers:
      - type: word
        words:
          - "path preserved"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL+"/es/", nil)
	require.NoError(t, err)
	require.NotNil(t, result, "got path %s", gotPath)
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

func TestInternalExtractorEventDoesNotOverwritePreviousMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/match":
			w.WriteHeader(200)
			fmt.Fprint(w, "already matched")
		case "/extract":
			w.WriteHeader(200)
			fmt.Fprint(w, "token=abc123")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Stock-nuclei shape: the first request matches and emits a result; the
	// second request only runs an internal extractor (no matchers), so its event
	// carries dynamic values but no match and must not overwrite the first match.
	yamlContent := `
id: internal-extractor-no-overwrite-test
info:
  name: Internal Extractor No Overwrite Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/match"
    matchers:
      - type: word
        words:
          - "already matched"

  - method: GET
    path:
      - "{{BaseURL}}/extract"
    extractors:
      - type: regex
        name: token
        regex:
          - "token=([a-z0-9]+)"
        group: 1
        internal: true
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	require.NoError(t, err)
	require.NoError(t, tmpl.Compile(nil))

	result, err := tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Contains(t, result.Request, "/match")
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
