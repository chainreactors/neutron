package convert

import (
	"strings"
	"testing"
)

func TestConvertSetVariablesOrdersDependenciesAndMapsHex(t *testing.T) {
	xray := `
name: set-variable-order
transport: http
set:
  h1: hex(rStr1)
  rStr1: randomLowercase(8)
rules:
  r0:
    request:
      method: GET
      path: /?q={{h1}}
    expression: response.status == 200 && response.body_string.contains(string(rStr1))
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	randIdx := strings.Index(converted, "rStr1:")
	hexIdx := strings.Index(converted, "h1:")
	if randIdx < 0 || hexIdx < 0 || randIdx > hexIdx {
		t.Fatalf("expected rStr1 before h1:\n%s", converted)
	}
	if !strings.Contains(converted, "{{hex_encode(rStr1)}}") {
		t.Fatalf("expected hex() to become hex_encode():\n%s", converted)
	}
}

func TestConvertSkipsRootURLSetWhenItMapsToBuiltin(t *testing.T) {
	xray := `
name: root-url-builtin
transport: http
set:
  RootURL: response.url.scheme + "://" + response.url.domain
rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        Origin: "{{RootURL}}"
    expression: response.status == 200
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, "true://true") {
		t.Fatalf("RootURL expression converted to invalid literal:\n%s", converted)
	}
	if strings.Contains(converted, "variables:") {
		t.Fatalf("RootURL should use neutron builtin instead of set variable:\n%s", converted)
	}
}

func TestConvertSetBytesVariableExpression(t *testing.T) {
	xray := `
name: set-bytes-variable
transport: http
set:
  token: md5("abc")
  token_bytes: bytes(token)
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body.bcontains(token_bytes)
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, "token_bytes: bytes(token)") {
		t.Fatalf("bytes(token) stayed literal:\n%s", converted)
	}
	if !strings.Contains(converted, `token_bytes: '{{token}}'`) {
		t.Fatalf("expected bytes(token) to reference token variable:\n%s", converted)
	}
}
