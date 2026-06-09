package convert

import (
	"strings"
	"testing"
)

func TestParseToAST(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"body_contains", `response.body_string.contains("hello")`, `contains(body, "hello")`},
		{"status_and_body", `response.status == 200 && response.body.contains("test")`, `((status_code == 200) && contains(body, "test"))`},
		{"header_access", `response.headers["Server"].contains("Apache")`, `contains(server, "Apache")`},
		{"raw_header_contains", `response.raw_header.bcontains(b"X-Jenkins")`, `contains(header, "X-Jenkins")`},
		{"raw_header_reverse_regex", `"Location: https://example.com".bmatches(response.raw_header)`, `regex("Location: https://example.com", header)`},
		{"header_in", `"Server" in response.headers`, `contains(all_headers, "server:")`},
		{"icontains", `response.body.icontains("Test")`, `icontains(body, "Test")`},
		{"regex", `response.body_string.matches("ver\\d+")`, `regex("ver\\d+", body)`},
		{"reverse_matches", `"pattern".matches(response.body_string)`, `regex("pattern", body)`},
		{"favicon", `faviconHash(response.getIconContent()) == -297069493`, `contains(favicon_hash, "-297069493")`},
		{"favicon_response_icon", `faviconHash(response.icon()) == 1677186191`, `contains(favicon_hash, "1677186191")`},
		{"mmh3_get_icon_content", `mmh3(response.getIconContent()) == 1677186191`, `contains(favicon_hash, "1677186191")`},
		{"mmh3_response_icon", `mmh3(response.icon()) == 1677186191`, `contains(favicon_hash, "1677186191")`},
		{"mmh3_icon", `mmh3(icon(response)) in [51234238, -1216867457]`, `(contains(favicon_hash, "51234238") || contains(favicon_hash, "-1216867457"))`},
		{"title_to_title", `response.title_string.contains("Login")`, `contains(title, "Login")`},
		{"string_title_contains", `string(response.title).contains("Sindoh")`, `contains(title, "Sindoh")`},
		{"literal_contains", `"a".contains("b")`, `contains("a", "b")`},
		{"cert_subject", `response.cert.issuer.contains("test")`, `icontains(cert_issuer, "test")`},
		{"cert_time_convert", `timeConvert(response.cert.not_before, "2006-01-02 03:04:05").icontains("2020")`, `icontains(time_convert(cert_not_before, concat("2", "0", "0", "6", "-", "0", "1", "-", "0", "2", " ", "0", "3", ":", "0", "4", ":", "0", "5")), "2020")`},
		// cert subfields beyond subject/issuer used to be silently dropped; they
		// now resolve via common.XrayCertFields (the single source of truth).
		// contains() on cert.* is folded to icontains() because X.509 DN casing
		// is not semantic (see caseFoldCertMatch).
		{"cert_dnsnames", `response.cert.dnsnames.contains("ingress-nginx")`, `icontains(cert_dnsnames, "ingress-nginx")`},
		{"cert_serial", `response.cert.serial.contains("12")`, `icontains(cert_serial, "12")`},
		{"cert_common_name", `response.cert.common_name.contains("leaf")`, `icontains(cert_common_name, "leaf")`},
		{"cert_cn_alias", `response.cert.cn.contains("leaf")`, `icontains(cert_common_name, "leaf")`},
		{"cert_organization", `response.cert.organization.contains("Acme")`, `icontains(cert_organization, "Acme")`},
		{"cert_org_alias", `response.cert.org.contains("Acme")`, `icontains(cert_organization, "Acme")`},
		{"cert_icontains_idempotent", `response.cert.issuer.icontains("RG-SMP")`, `icontains(cert_issuer, "RG-SMP")`},
		{"size_to_len", `size(response.body) < 100`, `(len(body) < 100)`},
		{"bytes_func", `response.body.bcontains(bytes("ITDR"))`, `contains(body, "ITDR")`},
		{"translate_literal", `response.body.bcontains(b"{{ 'Common.Title' | translate }}")`, `contains(body, "{{ \'Common.Title\' | translate }}")`},
		{"bytes_md5", `response.body.bcontains(bytes(md5(string(s1))))`, `contains(body, md5(to_string(s1)))`},
		{"arithmetic_latency", `response.latency - r0latency >= sleepSecond1 * 1000 - 1000`, `xray_gte(xray_sub(latency, r0latency), xray_sub(xray_mul(sleepSecond1, 1000), 1000))`},
		{"latency_less_extracted", `response.latency < r1latency`, `xray_lt(latency, r1latency)`},
		{"arithmetic_string", `response.body.contains(string(r1 * r2))`, `contains(body, to_string(xray_mul(r1, r2)))`},
		{"concat_string", `response.body.contains("<script>" + string(rand) + "</script>")`, `contains(body, concat(concat("<script>", to_string(rand)), "</script>"))`},
		{"bstarts_with", `response.body.bstartsWith(bytes("Salted__"))`, `starts_with(body, "Salted__")`},
		{"version_submatch", `"version\":\"(?P<version>.*)\"".submatch(response.body_string)["version"].versionEqual("8.0.0")`, `xray_version_equal(xray_regex_group("version\":\"(?P<version>.*)\"", body, "version"), "8.0.0")`},
		{"version_in", `versionIn("Stable tag: (?P<version>[0-9.]+)".submatch(response.body_string)["version"],"<= 5.1.16")`, `xray_version_in(xray_regex_group("Stable tag: (?P<version>[0-9.]+)", body, "version"), "<= 5.1.16")`},
		{"valid_page", `isValidPage(response)`, `xray_valid_page(status_code, body)`},
		{"replace_all", `replaceAll(tmp, "\\", "/")`, `replace(tmp, "\\", "/")`},
		{"randomstr_alias", `response.body.contains("x" + randomstr)`, `contains(body, concat("x", randstr))`},
		{"sha_alias", `sha(str1, "sha1") + "=" + sha(str2, "sha1")`, `concat(concat(xray_sha(str1, "sha1"), "="), xray_sha(str2, "sha1"))`},
		// \xNN hex escape sequences
		{"hex_escape_0c", `response.body.bcontains(b"\x0c")`, "contains(body, \"\\f\")"},
		{"hex_escape_gzip", `response.body.bstartsWith(b"\x1F\x8B")`, "starts_with(body, \"\\x1f\\u008b\")"},
		{"hex_escape_zip", `response.body.bstartsWith(b"PK\x03\x04")`, "starts_with(body, \"PK\\x03\\x04\")"},
		{"hex_escape_null", `response.body.bcontains(b"SQLite format 3\x00")`, "contains(body, \"SQLite format 3\\x00\")"},
		// triple-quoted raw strings
		{"triple_quote_regex", `r'''(?i)<input\b.+?type=["']?file['"]?'''.bmatches(response.body)`, "regex(\"(?i)<input\\\\b.+?type=[\\\"\\']?file[\\'\\\"]?\", body)"},
		// variable-indexed header access
		{"header_var_access", `response.headers[rHeader].startsWith(r1)`, `contains(all_headers, r1)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseToAST(tt.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := node.String()
			if got != tt.want {
				t.Errorf("got:  %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestExprToMatchers(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		wantN    int
		wantCond string
		check    func(t *testing.T, r *ConvertResult)
	}{
		{
			"simple_word", `response.body_string.contains("hello")`, 1, "or",
			func(t *testing.T, r *ConvertResult) {
				m := r.Matchers[0]
				if m.Type != "word" || m.Part != "body" || m.Words[0] != "hello" {
					t.Errorf("got %+v", m)
				}
			},
		},
		{
			"status_and_word", `response.status == 200 && response.body.contains("admin")`, 2, "and",
			func(t *testing.T, r *ConvertResult) {
				if r.Matchers[0].Type != "status" {
					t.Errorf("m0 type: %s", r.Matchers[0].Type)
				}
				if r.Matchers[1].Type != "word" {
					t.Errorf("m1 type: %s", r.Matchers[1].Type)
				}
			},
		},
		{
			"and_words_merged",
			`response.body.contains("wp-content") && response.body.contains("wp-includes")`,
			1, "and",
			func(t *testing.T, r *ConvertResult) {
				m := r.Matchers[0]
				if m.Type != "word" || len(m.Words) != 2 || m.Condition != "and" {
					t.Errorf("got %+v", m)
				}
			},
		},
		{
			"header_dsl", `response.headers['Server'].contains("Apache")`, 1, "or",
			func(t *testing.T, r *ConvertResult) {
				m := r.Matchers[0]
				if m.Type != "dsl" {
					t.Errorf("expected dsl matcher for individual header, got %+v", m)
				}
			},
		},
		{
			"favicon_hash", `faviconHash(response.getIconContent()) == -297069493`, 1, "or",
			func(t *testing.T, r *ConvertResult) {
				m := r.Matchers[0]
				if m.Type != "favicon" || m.Part != "favicon_hash" || m.Hash[0] != "-297069493" {
					t.Errorf("got %+v", m)
				}
			},
		},
		{
			"mmh3_favicon_content", `mmh3(response.getIconContent()) == -297069493`, 1, "or",
			func(t *testing.T, r *ConvertResult) {
				m := r.Matchers[0]
				if m.Type != "favicon" || m.Part != "favicon_hash" || m.Hash[0] != "-297069493" {
					t.Errorf("got %+v", m)
				}
			},
		},
		{
			"body_favicon_hash", `faviconHash(response.body) == 123`, 1, "or",
			func(t *testing.T, r *ConvertResult) {
				m := r.Matchers[0]
				if m.Type != "favicon" || m.Part != "body_favicon_hash" || m.Hash[0] != "123" {
					t.Errorf("got %+v", m)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ExprToMatchers(tt.expr)
			if err != nil {
				t.Fatalf("convert: %v", err)
			}
			if len(r.Matchers) != tt.wantN {
				for i, m := range r.Matchers {
					t.Logf("m[%d]: %+v", i, m)
				}
				t.Fatalf("count: got %d want %d", len(r.Matchers), tt.wantN)
			}
			if r.MatchersCondition != tt.wantCond {
				t.Errorf("condition: got %q want %q", r.MatchersCondition, tt.wantCond)
			}
			if tt.check != nil {
				tt.check(t, r)
			}
		})
	}
}

func TestConvert(t *testing.T) {
	xrayYAML := `
name: fingerprint-apache--tomcat
detail:
  fingerprint:
    name: Apache-Tomcat
    cpe: apache:tomcat
transport: http
rules:
  kw_in_home:
    request:
      method: GET
      path: /
      follow_redirects: false
    expression: |-
      response.body_string.contains("Apache Software Foundation")
      && response.body_string.contains("tomcat.apache.org")
  kw_in_server:
    request:
      method: GET
      path: /
    expression: response.headers['server'].contains('Apache-Coyote')
  favicon_hash:
    request:
      method: GET
      path: /
    expression: faviconHash(response.getIconContent()) == -297069493
expression: kw_in_home() || kw_in_server() || favicon_hash()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	s := string(out)
	t.Logf("output:\n%s", s)

	// Verify structure
	if !strings.Contains(s, "id: apache-tomcat") {
		t.Error("missing id")
	}
	if !strings.Contains(s, "type: word") {
		t.Error("missing word matcher")
	}
	if !strings.Contains(s, "type: favicon") {
		t.Error("missing favicon matcher")
	}
	if !strings.Contains(s, "condition: and") {
		t.Error("missing and condition for kw_in_home words")
	}
	if !strings.Contains(s, `contains(server, "Apache-Coyote")`) {
		t.Error("missing server DSL check")
	}
	// Should NOT contain xray_hdr_ prefix
	if strings.Contains(s, "xray_hdr_") {
		t.Error("output contains xray_hdr_ prefix — should use nuclei variable names")
	}
}

func TestConvertXraySetAndPayloadVariables(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--variables
detail:
  fingerprint:
    name: Variable Test
transport: http
set:
  randomPath: get404Path()
payloads:
  payloads:
    p0:
      value: '""'
    p1:
      value: '"admin/login"'
rules:
  payload_rule:
    request:
      method: GET
      path: /{{value}}
    expression: response.status == 200
  set_rule:
    request:
      method: GET
      path: /{{randomPath}}
    expression: response.status == 404
expression: payload_rule() || set_rule()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)

	if !strings.Contains(s, "variables:") || !strings.Contains(s, "randomPath: '{{rand_text_alphanumeric(16)}}'") {
		t.Fatalf("missing converted set variable:\n%s", s)
	}
	if !strings.Contains(s, "payloads:") || !strings.Contains(s, "value:") || !strings.Contains(s, "admin/login") {
		t.Fatalf("missing converted payload values:\n%s", s)
	}
	if !strings.Contains(s, "{{RootURL}}/{{value}}") {
		t.Fatalf("payload placeholder path was not preserved:\n%s", s)
	}
}

func TestConvertXraySetExpressionSemantics(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--set-expression-semantics
detail:
  fingerprint:
    name: Set Expression Semantics
transport: http
set:
  time: int(now()) * 1000
  token: base64("prefix:" + string(time))
  referer: request.url.scheme+"://"+ request.url.host
rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        X-Token: "{{token}}"
        Referer: "{{referer}}"
    expression: response.status == 200
expression: r0()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)
	for _, want := range []string{
		`time: '{{xray_mul(to_number(unix_time()), 1000)}}'`,
		`token: '{{base64(concat("prefix:", to_string(time)))}}'`,
		`referer: '{{concat(concat(Scheme, "://"), Hostname)}}'`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in converted output:\n%s", want, s)
		}
	}
}

func TestConvertXrayLatencyOutputExtractor(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--latency-output
transport: http
rules:
  baseline:
    request:
      method: GET
      path: /
    expression: response.status == 200
    output:
      r0latency: response.latency
  delayed:
    request:
      method: GET
      path: /slow
    expression: response.latency - r0latency >= 1000
expression: baseline() && delayed()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)
	for _, want := range []string{
		"type: dsl",
		"name: r0latency",
		"dsl:",
		"- latency",
		"xray_sub(latency, r0latency)",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in converted output:\n%s", want, s)
		}
	}
}

func TestConvertReqConditionDoesNotSuffixDynamicVariables(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--latency-dynamic-vars
transport: http
set:
  sleepSecond1: randomInt(5, 8)
rules:
  baseline:
    request:
      method: GET
      path: /base
    expression: response.status == 200
    output:
      r0latency: response.latency
  delayed:
    request:
      method: GET
      path: /delay/{{sleepSecond1}}
    expression: response.latency - r0latency >= sleepSecond1 * 1000
  compare:
    request:
      method: GET
      path: /compare
    expression: response.latency < r0latency
expression: baseline() && delayed() && compare()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)

	for _, bad := range []string{"r0latency_1", "r0latency_2", "sleepSecond1_1", "sleepSecond1_2"} {
		if strings.Contains(s, bad) {
			t.Fatalf("dynamic variable was suffixed as %q:\n%s", bad, s)
		}
	}
	if !strings.Contains(s, "latency_2") || !strings.Contains(s, "status_code_1") {
		t.Fatalf("response variables should still be suffixed:\n%s", s)
	}
}

func TestConvertXrayReverseUnsupported(t *testing.T) {
	xrayYAML := `
name: poc-reverse
transport: http
set:
  reverse: newReverse()
  reverseURL: reverse.url
rules:
  r0:
    request:
      method: GET
      path: /
    expression: reverse.wait(5)
expression: r0()
`
	_, err := Convert([]byte(xrayYAML))
	if err == nil || !strings.Contains(err.Error(), "unsupported xray reverse/oob") {
		t.Fatalf("expected unsupported reverse error, got %v", err)
	}
}

func TestConvertXrayOutputVariableExtractor(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--output-variable
detail:
  fingerprint:
    name: Output Variable Test
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("app.js")
    output:
      search: '"src=\"(?P<js_path>/static/app\.[a-z0-9]+\.js)\"".submatch(response.body_string)'
      js_path: search["js_path"]
  fetch_js:
    request:
      method: GET
      path: /{{js_path}}
    expression: response.body_string.contains("boot")
expression: discover() && fetch_js()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)

	for _, want := range []string{
		"extractors:",
		"name: js_path",
		"internal: true",
		`{{RootURL}}/{{trim_prefix(js_path, "/")}}`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in converted output:\n%s", want, s)
		}
	}
}

func TestConvertXrayOutputTransformExtractor(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--output-transform
transport: http
rules:
  upload:
    request:
      method: POST
      path: /upload
    expression: response.status == 200
    output:
      search: |-
        "(?P<path>public\\\\/shell.php)".bsubmatch(response.body)
      path: replaceAll(search["path"], "\\", "")
  fetch:
    request:
      method: GET
      path: /{{path}}
    expression: response.status == 200
expression: upload() && fetch()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)

	for _, want := range []string{
		"name: path_raw",
		"name: path",
		`replace(path_raw, "\\", "")`,
		`{{RootURL}}/{{trim_prefix(path, "/")}}`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in converted output:\n%s", want, s)
		}
	}
}

func TestConvertXrayRawStringPreservesRegexEscapes(t *testing.T) {
	xrayYAML := `
name: fingerprint-test--raw-regex-output
detail:
  fingerprint:
    name: Raw Regex Output Test
transport: http
rules:
  discover:
    request:
      method: GET
      path: /
    expression: response.body_string.contains("location")
    output:
      search: r'location="(?P<nextpath>[\/\w]+)'.submatch(response.body_string)
      nextpath: search["nextpath"]
  follow:
    request:
      method: GET
      path: /{{nextpath}}
    expression: response.body_string.contains("ok")
expression: discover() && follow()
`
	out, err := Convert([]byte(xrayYAML))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	s := string(out)
	t.Logf("output:\n%s", s)

	for _, want := range []string{
		`location="(?P<nextpath>[\/\w]+)`,
		`{{RootURL}}/{{trim_prefix(nextpath, "/")}}`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in converted output:\n%s", want, s)
		}
	}
}
