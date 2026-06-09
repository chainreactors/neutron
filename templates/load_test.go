package templates

import (
	"testing"

	_ "github.com/chainreactors/neutron/protocols/http"

	protohttp "github.com/chainreactors/neutron/protocols/http"
)

const neutronTemplateYAML = `
id: example-template
info:
  name: Example
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "rules"
`

// With no converter registered for it, a native neutron template is parsed
// directly and passed through verbatim. (Cross-format conversion via a
// registered converter is exercised in the convert package's tests.)
func TestLoadNeutronPassthrough(t *testing.T) {
	if got := DetectFormat([]byte(neutronTemplateYAML)); got != "neutron" {
		t.Fatalf("DetectFormat = %q, want neutron", got)
	}
	tmpl, err := Load([]byte(neutronTemplateYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tmpl.Id != "example-template" {
		t.Errorf("expected id example-template, got %q", tmpl.Id)
	}
	reqs := tmpl.GetRequests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	httpReq, ok := reqs[0].(*protohttp.Request)
	if !ok {
		t.Fatal("expected HTTP request type")
	}
	if len(httpReq.Matchers) != 1 || httpReq.Matchers[0].Words[0] != "rules" {
		t.Errorf("neutron template was not passed through verbatim: %+v", httpReq.Matchers)
	}
}
