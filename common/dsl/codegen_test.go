package dsl

import (
	"testing"
)

func TestGenerateFOFA(t *testing.T) {
	e := &FOFAEmitter{}
	tests := []struct {
		expr string
		want string
	}{
		{`contains(body, "test")`, `body="test"`},
		{`contains(body, "admin") && status_code == 200`, `body="admin" && status_code="200"`},
		{`contains(body, "a") || contains(header, "b")`, `body="a" || header="b"`},
		{`contains(body, "x") && contains(body, "y") && status_code == 200`, `body="x" && body="y" && status_code="200"`},
		{`contains(body, "wp-login") && contains(header, "text/html")`, `body="wp-login" && header="text/html"`},
		{`contains_all(body, "admin", "login")`, `(body="admin" && body="login")`},
		{`contains_any(body, "admin", "root")`, `(body="admin" || body="root")`},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			r := Generate(node, e)
			if r.Query != tt.want {
				t.Errorf("got %q, want %q", r.Query, tt.want)
			}
			if r.HasErrors() {
				t.Errorf("unexpected errors: %v", r.Errors)
			}
		})
	}
}

func TestGenerateHunter(t *testing.T) {
	e := &HunterEmitter{}
	tests := []struct {
		expr string
		want string
	}{
		{`contains(body, "login")`, `body="login"`},
		{`contains(header, "Apache") && status_code == 200`, `header="Apache" && status_code="200"`},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			r := Generate(node, e)
			if r.Query != tt.want {
				t.Errorf("got %q, want %q", r.Query, tt.want)
			}
		})
	}
}

func TestGenerateCensys(t *testing.T) {
	e := &CensysEmitter{}
	tests := []struct {
		expr string
		want string
	}{
		{
			`contains(body, "test")`,
			`services.http.response.body: "test"`,
		},
		{
			`contains(body, "admin") && status_code == 200`,
			`services.http.response.body: "admin" AND services.http.response.status_code: 200`,
		},
		{
			`contains(body, "a") || contains(header, "b")`,
			`services.http.response.body: "a" OR services.http.response.headers: "b"`,
		},
		{
			`contains_all(body, "x", "y")`,
			`(services.http.response.body: "x" AND services.http.response.body: "y")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			r := Generate(node, e)
			if r.Query != tt.want {
				t.Errorf("got %q, want %q", r.Query, tt.want)
			}
			if r.HasErrors() {
				t.Errorf("unexpected errors: %v", r.Errors)
			}
		})
	}
}

func TestGenerateWarnings(t *testing.T) {
	e := &FOFAEmitter{}

	node, err := Parse(`starts_with(body, "prefix")`)
	if err != nil {
		t.Fatal(err)
	}
	r := Generate(node, e)
	if len(r.Warnings) == 0 {
		t.Error("expected warning for starts_with")
	}
	if r.Query != `body="prefix"` {
		t.Errorf("got %q, want body=\"prefix\"", r.Query)
	}
}

func TestGenerateUnsupportedFunction(t *testing.T) {
	e := &FOFAEmitter{}

	node, err := Parse(`regex("pattern", body)`)
	if err != nil {
		t.Fatal(err)
	}
	r := Generate(node, e)
	if !r.HasErrors() {
		t.Error("expected error for regex function")
	}
}

func TestGenerateNot(t *testing.T) {
	e := &FOFAEmitter{}

	node, err := Parse(`!contains(body, "error")`)
	if err != nil {
		t.Fatal(err)
	}
	r := Generate(node, e)
	if r.Query != `!(body="error")` {
		t.Errorf("got %q, want %q", r.Query, `!(body="error")`)
	}
}

func TestGetEmitter(t *testing.T) {
	for _, name := range []string{"fofa", "hunter", "censys"} {
		e, ok := GetEmitter(name)
		if !ok || e == nil {
			t.Errorf("GetEmitter(%q) returned nil", name)
		}
	}
	_, ok := GetEmitter("nonexistent")
	if ok {
		t.Error("expected false for nonexistent emitter")
	}
}

func TestGenerateNewFields(t *testing.T) {
	tests := []struct {
		expr   string
		fofa   string
		hunter string
		censys string
	}{
		{
			`contains(server, "nginx")`,
			`server="nginx"`,
			`server="nginx"`,
			`services.http.response.headers.server: "nginx"`,
		},
		{
			`contains(banner, "SSH-2.0")`,
			`banner="SSH-2.0"`,
			`banner="SSH-2.0"`,
			`services.banner: "SSH-2.0"`,
		},
		{
			`contains(cert, "Let's Encrypt")`,
			`cert="Let's Encrypt"`,
			`cert="Let's Encrypt"`,
			`services.certificate: "Let's Encrypt"`,
		},
		{
			`contains(cert_subject, "Example Corp")`,
			`cert.subject="Example Corp"`,
			`cert.subject="Example Corp"`,
			`services.tls.certificates.leaf_data.subject.common_name: "Example Corp"`,
		},
		{
			`contains(cert_issuer, "DigiCert")`,
			`cert.issuer="DigiCert"`,
			`cert.issuer="DigiCert"`,
			`services.tls.certificates.leaf_data.issuer.common_name: "DigiCert"`,
		},
		{
			`contains(protocol, "https")`,
			`protocol="https"`,
			`protocol="https"`,
			`services.service_name: "https"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}

			expected := map[string]string{"fofa": tt.fofa, "hunter": tt.hunter, "censys": tt.censys}
			for platform, want := range expected {
				e, _ := GetEmitter(platform)
				r := Generate(node, e)
				if r.Query != want {
					t.Errorf("[%s] got %q, want %q", platform, r.Query, want)
				}
			}
		})
	}
}

func TestEndToEndAllEngines(t *testing.T) {
	expr := `contains(body, "wp-content") && contains(body, "wp-includes")`
	expected := map[string]string{
		"fofa":   `body="wp-content" && body="wp-includes"`,
		"hunter": `body="wp-content" && body="wp-includes"`,
		"censys": `services.http.response.body: "wp-content" AND services.http.response.body: "wp-includes"`,
	}

	node, err := Parse(expr)
	if err != nil {
		t.Fatal(err)
	}

	for platform, want := range expected {
		t.Run(platform, func(t *testing.T) {
			e, _ := GetEmitter(platform)
			r := Generate(node, e)
			if r.Query != want {
				t.Errorf("got %q, want %q", r.Query, want)
			}
		})
	}
}
