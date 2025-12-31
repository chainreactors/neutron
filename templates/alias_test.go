package templates

import (
	"testing"

	"gopkg.in/yaml.v3"
)

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
