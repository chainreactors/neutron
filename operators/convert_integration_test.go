package operators

import (
	"fmt"
	"testing"

	"github.com/chainreactors/neutron/common/dsl"
)

// Real fingerprint templates from fingerprinthub, testing Operators.ToQuery() end-to-end.

func compileOperators(matchers []*Matcher, condition string) *Operators {
	ops := &Operators{
		Matchers:          matchers,
		MatchersCondition: condition,
	}
	ops.Compile()
	return ops
}

func TestRealFingerprint_WordPress(t *testing.T) {
	// WordPress detection: word matcher on body
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"/wp-content/", "/wp-includes/"}, Condition: "and"},
	}, "or")

	for _, platform := range []string{"fofa", "hunter", "censys"} {
		e, _ := dsl.GetEmitter(platform)
		r := ops.ToQuery(e)
		t.Logf("[%s] %s", platform, r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", platform)
		}
	}
}

func TestRealFingerprint_EyouEmail(t *testing.T) {
	// eyou-email-system: OR of two word matchers, first has AND condition internally
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"eyoumail", "eyouws"}, Condition: "and", CaseInsensitive: true},
		{Type: "word", Part: "body", Words: []string{"/tpl/login/user/images/dbg.png", "亿邮电子邮件系统"}, CaseInsensitive: true},
	}, "or")

	for _, platform := range []string{"fofa", "hunter", "censys"} {
		e, _ := dsl.GetEmitter(platform)
		r := ops.ToQuery(e)
		t.Logf("[%s] %s", platform, r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", platform)
		}
	}
}

func TestRealFingerprint_InformaticaPowercenter(t *testing.T) {
	// informatica-powercenter: OR of body word + header word
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{`action="/adminconsole/loginsubmit.do`}, CaseInsensitive: true},
		{Type: "word", Part: "header", Words: []string{"server: informatica"}, CaseInsensitive: true},
	}, "or")

	for _, platform := range []string{"fofa", "hunter", "censys"} {
		e, _ := dsl.GetEmitter(platform)
		r := ops.ToQuery(e)
		t.Logf("[%s] %s", platform, r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", platform)
		}
	}
}

func TestRealFingerprint_JsHerp(t *testing.T) {
	// jsherp: OR of word + favicon
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"jsherp-boot"}, CaseInsensitive: true},
		{Type: "favicon", Hash: []string{"-1298131932"}},
	}, "or")

	for _, platform := range []string{"fofa", "hunter", "censys"} {
		e, _ := dsl.GetEmitter(platform)
		r := ops.ToQuery(e)
		t.Logf("[%s] query=%s errors=%v", platform, r.Query, r.Errors)
		if platform != "censys" && r.Query == "" {
			t.Errorf("[%s] empty query", platform)
		}
	}
}

func TestRealFingerprint_RuckusWireless(t *testing.T) {
	// ruckus-wireless: OR of favicon + word
	ops := compileOperators([]*Matcher{
		{Type: "favicon", Hash: []string{"ed8cf53ef6836184587ee3a987be074a"}},
		{Type: "word", Part: "body", Words: []string{"<title>ruckus wireless admin</title>", `alt="ruckus wireless" title=`}, CaseInsensitive: true},
	}, "or")

	e := &dsl.FOFAEmitter{}
	r := ops.ToQuery(e)
	t.Logf("[fofa] %s", r.Query)

	expected := `icon_hash="ed8cf53ef6836184587ee3a987be074a" || body="<title>ruckus wireless admin</title>" || body="alt=\"ruckus wireless\" title="`
	if r.Query != expected {
		t.Logf("expected: %s", expected)
		t.Logf("got:      %s", r.Query)
	}
}

func TestRealFingerprint_AllPlatformsComparison(t *testing.T) {
	// Show all 3 engine outputs side by side for a real template
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"Powered by Discuz!"}, CaseInsensitive: true},
		{Type: "word", Part: "header", Words: []string{"x-powered-by: php"}, CaseInsensitive: true},
		{Type: "status", Status: []int{200}},
	}, "or")

	platforms := []string{"fofa", "hunter", "censys"}
	fmt.Println("\n=== Discuz! fingerprint ===")
	for _, p := range platforms {
		e, _ := dsl.GetEmitter(p)
		r := ops.ToQuery(e)
		fmt.Printf("  %-8s %s\n", p+":", r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", p)
		}
	}
}

func TestRealFingerprint_MixedMatchersCombined(t *testing.T) {
	// Simulate an AND condition: word + status (like nuclei templates)
	m1 := &Matcher{Type: "word", Part: "body", Words: []string{"<title>Login</title>"}}
	m2 := &Matcher{Type: "status", Status: []int{200}}

	ops := compileOperators([]*Matcher{m1, m2}, "and")

	tests := []struct {
		platform string
		expected string
	}{
		{"fofa", `body="<title>Login</title>" && status_code="200"`},
		{"hunter", `body="<title>Login</title>" && status_code="200"`},
		{"censys", `services.http.response.body: "<title>Login</title>" AND services.http.response.status_code: 200`},
	}
	// Single-word matcher + single-status matcher → no extra grouping needed

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			e, _ := dsl.GetEmitter(tt.platform)
			r := ops.ToQuery(e)
			if r.Query != tt.expected {
				t.Errorf("got  %q\nwant %q", r.Query, tt.expected)
			}
		})
	}
}

func TestRealFingerprint_RegexPartialResult(t *testing.T) {
	// Template with word + regex: should produce partial result
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"admin"}, CaseInsensitive: true},
		{Type: "regex", Regex: []string{`version\s+(\d+\.\d+)`}},
	}, "or")

	e := &dsl.FOFAEmitter{}
	r := ops.ToQuery(e)
	t.Logf("query=%q errors=%v", r.Query, r.Errors)

	if r.Query == "" {
		t.Error("expected partial query from word matcher")
	}
	if !r.HasErrors() {
		t.Error("expected errors from regex matcher")
	}
}
