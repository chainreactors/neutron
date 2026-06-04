package convert

import (
	"strings"
	"testing"

	"github.com/chainreactors/neutron/templates"
	"gopkg.in/yaml.v3"
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
	if strings.Contains(converted, "xray_RootURL") {
		t.Fatalf("RootURL builtin should not be rewritten to a missing alias:\n%s", converted)
	}
	if !strings.Contains(converted, "Origin: '{{RootURL}}'") {
		t.Fatalf("expected RootURL placeholder to keep neutron builtin:\n%s", converted)
	}
}

func TestConvertRenamesBuiltinSetVariable(t *testing.T) {
	xray := `
name: builtin-variable-collision
transport: http
set:
  BaseURL: request.url.domain
rules:
  r0:
    request:
      method: POST
      path: /admin/auth/reset-password
      headers:
        Origin: https://{{BaseURL}}
    expression: response.status == 200
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, "\n  BaseURL:") {
		t.Fatalf("xray set variable should not override neutron BaseURL:\n%s", converted)
	}
	if !strings.Contains(converted, "xray_BaseURL: '{{Host}}'") {
		t.Fatalf("expected colliding set variable to be renamed:\n%s", converted)
	}
	if !strings.Contains(converted, "Origin: https://{{xray_BaseURL}}") {
		t.Fatalf("expected original header placeholder to use renamed variable:\n%s", converted)
	}
	if !strings.Contains(converted, "{{BaseURL}}/admin/auth/reset-password") {
		t.Fatalf("expected converted request path to keep neutron BaseURL builtin:\n%s", converted)
	}
}

func TestConvertBuiltinSetVariableCanReferenceTargetBuiltin(t *testing.T) {
	xray := `
name: builtin-variable-target-reference
transport: http
set:
  Hostname: request.url.host
rules:
  r0:
    request:
      method: GET
      path: /maint/index.php
      headers:
        Referer: '{{Hostname}}/maint/index.php'
    expression: response.status == 200
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if !strings.Contains(converted, "xray_Hostname: '{{Hostname}}'") {
		t.Fatalf("expected aliased xray variable to reference neutron Hostname builtin:\n%s", converted)
	}
	if strings.Contains(converted, "xray_Hostname: '{{xray_Hostname}}'") {
		t.Fatalf("aliased set variable should not reference itself:\n%s", converted)
	}
	if !strings.Contains(converted, "Referer: '{{xray_Hostname}}/maint/index.php'") {
		t.Fatalf("expected original placeholder to use aliased variable:\n%s", converted)
	}
	assertConvertedCompiles(t, out)
}

func TestConvertSetStringLiteralAndUpperFunction(t *testing.T) {
	xray := `
name: set-string-upper
transport: http
set:
  eps_path: string("/eps/api/resourceOperations/uploadsecretKeyIbuilding")
  token: upper(md5(eps_path))
rules:
  r0:
    request:
      method: GET
      path: /upload?token={{token}}
    expression: response.status == 200
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, `eps_path: string(`) {
		t.Fatalf("string() set expression should become a literal:\n%s", converted)
	}
	if !strings.Contains(converted, `eps_path: /eps/api/resourceOperations/uploadsecretKeyIbuilding`) {
		t.Fatalf("expected string() literal value in variables:\n%s", converted)
	}
	if strings.Contains(converted, `{{upper(`) {
		t.Fatalf("upper() should be translated to neutron DSL:\n%s", converted)
	}
	if !strings.Contains(converted, `token: '{{to_upper(md5(eps_path))}}'`) {
		t.Fatalf("expected upper() to become to_upper():\n%s", converted)
	}
}

func TestConvertRevFunction(t *testing.T) {
	xray := `
name: rev-function
transport: http
set:
  s1: randomLowercase(8)
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body_string.contains(rev(s1))
expression: r0()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, `rev(s1)`) {
		t.Fatalf("rev() should be translated to neutron DSL:\n%s", converted)
	}
	if !strings.Contains(converted, `contains(body, reverse(s1))`) {
		t.Fatalf("expected rev() to become reverse():\n%s", converted)
	}
}

func TestConvertAliasesReservedOutputVariable(t *testing.T) {
	xray := `
name: output-reserved-variable
transport: http
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200
    output:
      len: size(response.body)
      total: int(len / 2)
      hexed: decToHex(total)
  r1:
    request:
      method: GET
      path: /next/{{hexed}}
    expression: response.status == 200
expression: r0() && r1()
`
	out, err := Convert([]byte(xray))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	converted := string(out)
	if strings.Contains(converted, "\n          name: len\n") {
		t.Fatalf("reserved output variable should be renamed:\n%s", converted)
	}
	if !strings.Contains(converted, "name: xray_len") {
		t.Fatalf("expected len output variable to be aliased:\n%s", converted)
	}
	if strings.Contains(converted, "xray_div(len, 2)") {
		t.Fatalf("reserved output variable reference was not aliased:\n%s", converted)
	}
	if !strings.Contains(converted, "xray_div(xray_len, 2)") {
		t.Fatalf("expected output expression to reference aliased variable:\n%s", converted)
	}
	if !strings.Contains(converted, "dec_to_hex(total)") {
		t.Fatalf("expected decToHex() to become dec_to_hex():\n%s", converted)
	}
	assertConvertedCompiles(t, out)
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

func assertConvertedCompiles(t *testing.T, out []byte) {
	t.Helper()
	var tmpl templates.Template
	if err := yaml.Unmarshal(out, &tmpl); err != nil {
		t.Fatalf("unmarshal converted template: %v\n%s", err, out)
	}
	if err := tmpl.Compile(nil); err != nil {
		t.Fatalf("compile converted template: %v\n%s", err, out)
	}
}
