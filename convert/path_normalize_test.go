package convert

import (
	"strings"
	"testing"
)

func TestConvertStripsXrayPathAnchor(t *testing.T) {
	xray := `
name: anchored-path
transport: http
rules:
  r0:
    request:
      method: GET
      path: ^/admin
    expression: response.body_string.contains("admin")
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, "{{BaseURL}}^/admin") {
		t.Fatalf("path anchor was not stripped:\n%s", converted)
	}
	if !strings.Contains(converted, "{{BaseURL}}/admin") {
		t.Fatalf("normalized path missing:\n%s", converted)
	}
}
