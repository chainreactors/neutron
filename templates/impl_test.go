package templates

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestHTTPActiveRequest 测试 HTTP 主动请求和匹配
func TestHTTPActiveRequest(t *testing.T) {
	t.Log("========== HTTP Active Request Test ==========")

	// 使用一个公开的测试服务
	yamlContent := `
id: http-active-test
info:
  name: HTTP Active Request Test
  author: test
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "Example Domain"
        condition: or
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	if err != nil {
		t.Fatalf("Failed to unmarshal template: %v", err)
	}

	// 编译模板
	err = tmpl.Compile(nil)
	if err != nil {
		t.Fatalf("Failed to compile template: %v", err)
	}

	t.Logf("Template compiled successfully")
	t.Logf("  HTTP requests: %d", len(tmpl.GetRequests()))

	// 执行请求 - 使用 example.com 作为测试目标
	t.Log("\nExecuting HTTP request to http://example.com...")
	result, err := tmpl.Execute("http://example.com", nil)

	if err != nil {
		t.Logf("Execute error: %v", err)
		// 网络错误是可以接受的
		if err == protocols.OpsecError {
			t.Skip("Opsec mode enabled, skipping")
		}
	}

	if result != nil {
		t.Logf("✅ HTTP request executed successfully")
		t.Logf("   Matched: %v", result.Matched)
		if result.Matched {
			t.Log("   ✅ Matchers matched the response!")
		}
	} else {
		t.Log("⚠️  No result returned (may need network access)")
	}
}

// TestNetworkActiveRequest 测试 Network 主动连接和匹配
func TestNetworkActiveRequest(t *testing.T) {
	t.Log("========== Network Active Request Test ==========")

	// 测试连接到本地 PostgreSQL
	yamlContent := `
id: network-active-test
info:
  name: Network Active Request Test
  author: test
  severity: info

network:
  - inputs:
      - data: "0000000800030000"
        type: hex
        read: 1024

    host:
      - "{{Hostname}}"

    matchers:
      - type: word
        words:
          - "SFATAL"
          - "startup"
        condition: or
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	if err != nil {
		t.Fatalf("Failed to unmarshal template: %v", err)
	}

	// 编译模板
	err = tmpl.Compile(nil)
	if err != nil {
		t.Fatalf("Failed to compile template: %v", err)
	}

	t.Logf("Template compiled successfully")
	t.Logf("  Network requests: %d", len(tmpl.RequestsNetwork))

	// 执行请求 - 连接到 localhost:5432
	t.Log("\nExecuting network request to 127.0.0.1:5432...")
	result, err := tmpl.Execute("127.0.0.1:5432", nil)

	if err != nil {
		t.Logf("Execute error: %v", err)
		if err == protocols.OpsecError {
			t.Skip("Opsec mode enabled, skipping")
		}
	}

	if result != nil {
		t.Logf("✅ Network request executed successfully")
		t.Logf("   Matched: %v", result.Matched)
		if result.Matched {
			t.Log("   ✅ Matchers matched the response!")
		} else {
			t.Log("   ⚠️  Response received but didn't match")
		}
	} else {
		t.Log("⚠️  No result returned")
	}
}

// TestTCPActiveRequest 测试使用 tcp 字段的主动连接
func TestTCPActiveRequest(t *testing.T) {
	t.Log("========== TCP Active Request Test ==========")

	// 使用 tcp 别名字段
	yamlContent := `
id: tcp-active-test
info:
  name: TCP Active Request Test
  author: test
  severity: info

tcp:
  - inputs:
      - data: "0000000800030000"
        type: hex
        read: 1024

    host:
      - "{{Hostname}}"

    matchers:
      - type: word
        words:
          - "SFATAL"
        condition: or
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	if err != nil {
		t.Fatalf("Failed to unmarshal template: %v", err)
	}

	// 编译模板
	err = tmpl.Compile(nil)
	if err != nil {
		t.Fatalf("Failed to compile template: %v", err)
	}

	t.Logf("Template compiled successfully")
	t.Logf("  TCP requests (as RequestsNetwork): %d", len(tmpl.RequestsNetwork))

	// 执行请求
	t.Log("\nExecuting TCP request to 127.0.0.1:5432...")
	result, err := tmpl.Execute("127.0.0.1:5432", nil)

	if err != nil {
		t.Logf("Execute error: %v", err)
	}

	if result != nil {
		t.Logf("✅ TCP request executed successfully")
		t.Logf("   Matched: %v", result.Matched)
		if result.Matched {
			t.Log("   ✅ TCP alias field works for active scanning!")
		}
	} else {
		t.Log("⚠️  No result returned")
	}
}

// TestExtractorActiveRequest 测试使用 extractor 的主动请求
func TestExtractorActiveRequest(t *testing.T) {
	t.Log("========== Extractor Active Request Test ==========")

	yamlContent := `
id: extractor-test
info:
  name: Extractor Test
  author: test
  severity: info

network:
  - inputs:
      - data: "0000000800030000"
        type: hex
        read: 1024

    host:
      - "{{Hostname}}"

    extractors:
      - type: regex
        name: error_code
        regex:
          - "C([0-9A-Z]+)"
`
	var tmpl Template
	err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
	if err != nil {
		t.Fatalf("Failed to unmarshal template: %v", err)
	}

	// 编译模板
	err = tmpl.Compile(nil)
	if err != nil {
		t.Fatalf("Failed to compile template: %v", err)
	}

	t.Logf("Template compiled successfully")

	// 执行请求
	t.Log("\nExecuting network request with extractor...")
	result, err := tmpl.Execute("127.0.0.1:5432", nil)

	if err != nil {
		t.Logf("Execute error: %v", err)
	}

	if result != nil {
		t.Logf("✅ Request executed")
		t.Logf("   Matched: %v", result.Matched)
		t.Logf("   Extracts: %v", result.OutputExtracts)
		if len(result.OutputExtracts) > 0 {
			t.Log("   ✅ Extractor successfully extracted data!")
		}
	} else {
		t.Log("⚠️  No result returned")
	}
}

// TestTCPUDPFieldAlias 测试 tcp 和 udp 字段作为 network 的别名
func TestTCPUDPFieldAlias(t *testing.T) {
	t.Run("TCP field alias", func(t *testing.T) {
		yamlContent := `
id: test-tcp-alias
info:
  name: Test TCP Alias
  author: test
  severity: info

tcp:
  - inputs:
      - data: "TEST"
    host:
      - "{{Hostname}}"
    matchers:
      - type: word
        words:
          - "response"
`
		var tmpl Template
		err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
		if err != nil {
			t.Fatalf("Failed to unmarshal template: %v", err)
		}

		// 验证 tcp 字段被解析
		if len(tmpl.RequestsTCP) == 0 {
			t.Error("TCP requests should be parsed from 'tcp' field")
		}

		// 编译模板
		err = tmpl.Compile(nil)
		if err != nil {
			t.Fatalf("Failed to compile template: %v", err)
		}

		// 验证 tcp 请求被合并到 RequestsNetwork
		if len(tmpl.RequestsNetwork) == 0 {
			t.Error("TCP requests should be merged into RequestsNetwork after compile")
		}

		t.Logf("✅ TCP field successfully processed as network alias")
		t.Logf("   RequestsTCP: %d", len(tmpl.RequestsTCP))
		t.Logf("   RequestsNetwork: %d", len(tmpl.RequestsNetwork))
	})

	t.Run("UDP field alias", func(t *testing.T) {
		yamlContent := `
id: test-udp-alias
info:
  name: Test UDP Alias
  author: test
  severity: info

udp:
  - inputs:
      - data: "TEST"
    host:
      - "{{Hostname}}"
    matchers:
      - type: word
        words:
          - "response"
`
		var tmpl Template
		err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
		if err != nil {
			t.Fatalf("Failed to unmarshal template: %v", err)
		}

		// 验证 udp 字段被解析
		if len(tmpl.RequestsUDP) == 0 {
			t.Error("UDP requests should be parsed from 'udp' field")
		}

		// 编译模板
		err = tmpl.Compile(nil)
		if err != nil {
			t.Fatalf("Failed to compile template: %v", err)
		}

		// 验证 udp 请求被合并到 RequestsNetwork
		if len(tmpl.RequestsNetwork) == 0 {
			t.Error("UDP requests should be merged into RequestsNetwork after compile")
		}

		t.Logf("✅ UDP field successfully processed as network alias")
		t.Logf("   RequestsUDP: %d", len(tmpl.RequestsUDP))
		t.Logf("   RequestsNetwork: %d", len(tmpl.RequestsNetwork))
	})

	t.Run("Mixed tcp and udp fields", func(t *testing.T) {
		yamlContent := `
id: test-mixed-alias
info:
  name: Test Mixed Alias
  author: test
  severity: info

tcp:
  - inputs:
      - data: "TCP_TEST"
    host:
      - "{{Hostname}}"

udp:
  - inputs:
      - data: "UDP_TEST"
    host:
      - "{{Hostname}}"
`
		var tmpl Template
		err := yaml.Unmarshal([]byte(yamlContent), &tmpl)
		if err != nil {
			t.Fatalf("Failed to unmarshal template: %v", err)
		}

		// 验证两个字段都被解析
		if len(tmpl.RequestsTCP) == 0 {
			t.Error("TCP requests should be parsed")
		}
		if len(tmpl.RequestsUDP) == 0 {
			t.Error("UDP requests should be parsed")
		}

		// 编译模板
		err = tmpl.Compile(nil)
		if err != nil {
			t.Fatalf("Failed to compile template: %v", err)
		}

		// 验证两个请求都被合并到 RequestsNetwork
		expectedCount := len(tmpl.RequestsTCP) + len(tmpl.RequestsUDP)
		if len(tmpl.RequestsNetwork) != expectedCount {
			t.Errorf("Expected %d network requests, got %d", expectedCount, len(tmpl.RequestsNetwork))
		}

		t.Logf("✅ Mixed TCP/UDP fields successfully processed")
		t.Logf("   RequestsTCP: %d", len(tmpl.RequestsTCP))
		t.Logf("   RequestsUDP: %d", len(tmpl.RequestsUDP))
		t.Logf("   RequestsNetwork: %d", len(tmpl.RequestsNetwork))
	})
}

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
variables:
  named: '{{rand_base(8)}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}/create?token={{randstr}}&named={{named}}'

  - method: GET
    path:
      - '{{BaseURL}}/check?token={{randstr}}&named={{named}}'
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

func TestExecuteKeepsRandnumStableAcrossHTTPBlocks(t *testing.T) {
	var requestedCodes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		requestedCodes = append(requestedCodes, code)
		switch r.URL.Path {
		case "/create":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "created %s", code)
		case "/check":
			if code != "" && len(requestedCodes) >= 2 && code == requestedCodes[0] {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "found")
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: randnum-stability-test
info:
  name: Randnum Stability Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/create?code={{randnum}}'

  - method: GET
    path:
      - '{{BaseURL}}/check?code={{randnum}}'
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
	require.Len(t, requestedCodes, 2)
	require.Equal(t, requestedCodes[0], requestedCodes[1])
	require.NotEmpty(t, requestedCodes[0])

	firstCode := requestedCodes[0]
	requestedCodes = nil
	_, err = tmpl.Execute(server.URL, nil)
	require.NoError(t, err)
	require.Len(t, requestedCodes, 2)
	require.Equal(t, requestedCodes[0], requestedCodes[1])
	require.NotEqual(t, firstCode, requestedCodes[0], "randnum must regenerate between scans")
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

func TestExecuteExplicitFaviconBodyHashDSL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/custom.ico":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ICON-CONTENT-BYTES")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	yamlContent := `
id: explicit-favicon-body-hash-test
info:
  name: Explicit Favicon Body Hash Test
  author: test
  severity: info
http:
  - method: GET
    path:
      - '{{BaseURL}}/custom.ico'
    matchers:
      - type: favicon
        hash:
          - "592422342"
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
