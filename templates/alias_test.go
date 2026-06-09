package templates

import (
	"testing"

	_ "github.com/chainreactors/neutron/protocols/network"
	"gopkg.in/yaml.v3"
)

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
		if err := yaml.Unmarshal([]byte(yamlContent), &tmpl); err != nil {
			t.Fatalf("Failed to unmarshal template: %v", err)
		}

		if err := tmpl.Parse(); err != nil {
			t.Fatalf("Failed to parse template: %v", err)
		}
		if len(tmpl.GetRequests()) == 0 {
			t.Error("TCP alias should produce parsed requests")
		}
		t.Logf("TCP alias: %d requests parsed", len(tmpl.GetRequests()))
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
		if err := yaml.Unmarshal([]byte(yamlContent), &tmpl); err != nil {
			t.Fatalf("Failed to unmarshal template: %v", err)
		}

		if err := tmpl.Parse(); err != nil {
			t.Fatalf("Failed to parse template: %v", err)
		}
		if len(tmpl.GetRequests()) == 0 {
			t.Error("UDP alias should produce parsed requests")
		}
		t.Logf("UDP alias: %d requests parsed", len(tmpl.GetRequests()))
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
		if err := yaml.Unmarshal([]byte(yamlContent), &tmpl); err != nil {
			t.Fatalf("Failed to unmarshal template: %v", err)
		}

		if err := tmpl.Parse(); err != nil {
			t.Fatalf("Failed to parse template: %v", err)
		}
		if len(tmpl.GetRequests()) != 2 {
			t.Errorf("Expected 2 requests from mixed tcp+udp, got %d", len(tmpl.GetRequests()))
		}
		t.Logf("Mixed: %d requests parsed", len(tmpl.GetRequests()))
	})
}
