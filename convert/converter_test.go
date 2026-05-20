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
		{"header_in", `"Server" in response.headers`, `contains(all_headers, "server:")`},
		{"icontains", `response.body.icontains("Test")`, `icontains(body, "Test")`},
		{"regex", `response.body_string.matches("ver\\d+")`, `regex("ver\\d+", body)`},
		{"reverse_matches", `"pattern".matches(response.body_string)`, `regex("pattern", body)`},
		{"favicon", `faviconHash(response.getIconContent()) == -297069493`, `(favicon_hash("mock") == -297069493)`},
		{"title_to_title", `response.title_string.contains("Login")`, `contains(title, "Login")`},
		{"cert_stub", `response.cert.issuer.contains("test")`, `true`},
		{"size_to_len", `size(response.body) < 100`, `(len(body) < 100)`},
		{"bytes_func", `response.body.bcontains(bytes("ITDR"))`, `contains(body, "ITDR")`},
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
