package convert

import (
	"strings"
	"testing"
)

func TestConvertPreservesSequentialRulesWithRepeatedRequests(t *testing.T) {
	xray := `
name: sequential-repeated-request
transport: http
rules:
  create:
    request:
      method: POST
      path: /toggle
      body: create
    expression: response.status == 200
  check_created:
    request:
      method: GET
      path: /flag
    expression: response.status == 200
  delete:
    request:
      method: POST
      path: /toggle
      body: delete
    expression: response.status == 200
  check_deleted:
    request:
      method: GET
      path: /flag
    expression: response.status == 404
expression: create() && check_created() && delete() && check_deleted()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if got := strings.Count(converted, `{{BaseURL}}/toggle`); got != 2 {
		t.Fatalf("expected two toggle requests, got %d:\n%s", got, converted)
	}
	if got := strings.Count(converted, `{{BaseURL}}/flag`); got != 2 {
		t.Fatalf("expected two flag requests, got %d:\n%s", got, converted)
	}
	if !strings.Contains(converted, "status_code_2 == 200") || !strings.Contains(converted, "status_code == 404") {
		t.Fatalf("expected request-condition to reference both repeated GET responses:\n%s", converted)
	}
}
