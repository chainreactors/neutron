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

func TestGenerateStaticHexDecodeValue(t *testing.T) {
	e := &FOFAEmitter{}

	node, err := Parse(`starts_with(body, hex_decode("504b0304"))`)
	if err != nil {
		t.Fatal(err)
	}
	r := Generate(node, e)
	if r.Query != `body="PK\x03\x04"` {
		t.Errorf("got %q, want escaped zip magic", r.Query)
	}
	if r.HasErrors() {
		t.Errorf("unexpected errors: %v", r.Errors)
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

func TestGenerateHeaderVariablesUseAllHeadersNeedles(t *testing.T) {
	tests := []struct {
		expr   string
		fofa   string
		hunter string
		censys string
	}{
		{
			`contains(location, "/login")`,
			`header="location: /login"`,
			`header="location: /login"`,
			`services.http.response.headers: "location: /login"`,
		},
		{
			`contains(set_cookie, "JSESSIONID")`,
			`header="set_cookie: JSESSIONID"`,
			`header="set_cookie: JSESSIONID"`,
			`services.http.response.headers: "set_cookie: JSESSIONID"`,
		},
		{
			`contains(www_authenticate, "Basic")`,
			`header="www_authenticate: Basic"`,
			`header="www_authenticate: Basic"`,
			`services.http.response.headers: "www_authenticate: Basic"`,
		},
		{
			`location == "/admin"`,
			`header="location: /admin"`,
			`header="location: /admin"`,
			`services.http.response.headers: "location: /admin"`,
		},
		{
			`contains_all(location, "/one", "/two")`,
			`(header="location: /one" && header="location: /two")`,
			`(header="location: /one" && header="location: /two")`,
			`(services.http.response.headers: "location: /one" AND services.http.response.headers: "location: /two")`,
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
				if r.HasErrors() {
					t.Errorf("[%s] unexpected errors: %v", platform, r.Errors)
				}
			}
		})
	}
}

func TestGenerateStatusCodeStringAndWrappedComparisons(t *testing.T) {
	tests := []struct {
		expr string
		want string
	}{
		{`status_code == "200"`, `status_code="200"`},
		{`to_number(status_code) == "401"`, `status_code="401"`},
		{`status_code != "404"`, `!(status_code="404")`},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			r := Generate(node, &FOFAEmitter{})
			if r.Query != tt.want {
				t.Errorf("got %q, want %q", r.Query, tt.want)
			}
			if r.HasErrors() {
				t.Errorf("unexpected errors: %v", r.Errors)
			}
		})
	}
}

func TestGenerateHistoryVariablesNormalizeForQueries(t *testing.T) {
	tests := []struct {
		expr   string
		fofa   string
		censys string
	}{
		{
			`contains(body_0, "redirect")`,
			`body="redirect"`,
			`services.http.response.body: "redirect"`,
		},
		{
			`contains(headers_0, "location: /login")`,
			`header="location: /login"`,
			`services.http.response.headers: "location: /login"`,
		},
		{
			`status_0 == "302"`,
			`status_code="302"`,
			`services.http.response.status_code: 302`,
		},
		{
			`contains(location_1, "/login") && status_code_1 != "404"`,
			`header="location: /login" && !(status_code="404")`,
			`services.http.response.headers: "location: /login" AND NOT services.http.response.status_code: 404`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			if got := Generate(node, &FOFAEmitter{}).Query; got != tt.fofa {
				t.Errorf("[fofa] got %q, want %q", got, tt.fofa)
			}
			if got := Generate(node, &CensysEmitter{}).Query; got != tt.censys {
				t.Errorf("[censys] got %q, want %q", got, tt.censys)
			}
		})
	}
}

func TestIsFieldTransparentRegisteredCorrectly(t *testing.T) {
	transparent := []string{"to_lower", "to_upper", "to_number", "to_string", "trim_space"}
	for _, name := range transparent {
		if !IsFieldTransparent(name) {
			t.Errorf("%s should be field-transparent", name)
		}
	}
	notTransparent := []string{"md5", "base64", "len", "concat", "reverse", "hex_encode"}
	for _, name := range notTransparent {
		if IsFieldTransparent(name) {
			t.Errorf("%s should NOT be field-transparent", name)
		}
	}
}

func TestIsHeaderVariableUsesEmitterFieldMapping(t *testing.T) {
	tests := []struct {
		part     string
		platform string
		want     bool
	}{
		{"location", "fofa", true},
		{"set_cookie", "fofa", true},
		{"www_authenticate", "fofa", true},
		{"x_powered_by", "fofa", true},
		{"content_type", "fofa", true},
		{"body", "fofa", false},
		{"all_headers", "fofa", false},
		{"status_code", "fofa", false},
		{"server", "fofa", false},
		{"title", "fofa", false},
		// censys has a dedicated content_type field
		{"content_type", "censys", false},
		{"location", "censys", true},
	}
	for _, tt := range tests {
		e, _ := GetEmitter(tt.platform)
		got := isHeaderVariable(tt.part, e)
		if got != tt.want {
			t.Errorf("isHeaderVariable(%q, %s) = %v, want %v", tt.part, tt.platform, got, tt.want)
		}
	}
}

func TestGenerateUnmappedHeaderVariablesProduceNeedleQueries(t *testing.T) {
	tests := []struct {
		expr string
		fofa string
	}{
		{`contains(content_type, "json")`, `header="content_type: json"`},
		{`contains(x_powered_by, "PHP")`, `header="x_powered_by: PHP"`},
		{`x_forwarded_for == "127.0.0.1"`, `header="x_forwarded_for: 127.0.0.1"`},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			node, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			r := Generate(node, &FOFAEmitter{})
			if r.Query != tt.fofa {
				t.Errorf("got %q, want %q", r.Query, tt.fofa)
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
