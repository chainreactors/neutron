package convert

import (
	"testing"

	"github.com/chainreactors/neutron/templates"
)

const xrayPOCFixture = `
name: fingerprint-dingdian_network--08cms
detail:
  fingerprint:
    name: 08Cms
    cpe: dingdian_network:08cms
transport: http
rules:
  index_contains:
    expression: response.body_string.contains('/common/08cms.ico') ||
                response.body_string.contains("typeof(_08cms) != 'undefined'")
expression: index_contains()
`

const neutronTemplateFixture = `
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

func TestIsXrayPOC(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"xray poc", xrayPOCFixture, true},
		{"neutron http template", neutronTemplateFixture, false},
		{"neutron requests alias", "id: x\nrequests:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n", false},
		{"neutron network template", "id: x\nnetwork:\n  - host: [\"{{Hostname}}\"]\n", false},
		{"empty", "", false},
		{"garbage", "::: not yaml :::", false},
		{"detail fingerprint only", "name: foo\ndetail:\n  fingerprint:\n    name: Foo\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsXrayPOC([]byte(tt.in)); got != tt.want {
				t.Errorf("IsXrayPOC = %v, want %v", got, tt.want)
			}
		})
	}
}

// Importing this package runs its init(), which registers the xray converter,
// so templates.Load transparently converts xray POCs.
func TestTemplatesLoadConvertsXray(t *testing.T) {
	if got := templates.DetectFormat([]byte(xrayPOCFixture)); got != "xray" {
		t.Fatalf("DetectFormat = %q, want xray", got)
	}
	tmpl, err := templates.Load([]byte(xrayPOCFixture))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	reqs := tmpl.GetRequests()
	if len(reqs) == 0 {
		t.Fatalf("expected converted template to have http requests, got none")
	}
	if tmpl.Id == "" {
		t.Errorf("expected non-empty template id after conversion")
	}
	if err := tmpl.Compile(nil); err != nil {
		for _, req := range tmpl.GetRequests() {
			(&req.Operators).Compile()
			req.CompiledOperators = &req.Operators
		}
	}
	if len(reqs[0].Matchers) == 0 {
		t.Errorf("expected converted request to have matchers")
	}
}
