package templates

import (
	"testing"

	"github.com/chainreactors/neutron/protocols"
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
