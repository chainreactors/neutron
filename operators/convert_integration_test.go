package operators

import (
	"fmt"
	"testing"
)

func compileOperators(matchers []*Matcher, condition string) *Operators {
	ops := &Operators{
		Matchers:          matchers,
		MatchersCondition: condition,
	}
	ops.Compile()
	return ops
}

func TestRealFingerprint_WordPress(t *testing.T) {
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"/wp-content/", "/wp-includes/"}, Condition: "and"},
	}, "or")

	q := ops.ToQuery()
	for _, platform := range []string{"fofa", "hunter", "censys"} {
		r := q.Emit(platform)
		t.Logf("[%s] %s", platform, r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", platform)
		}
	}
}

func TestRealFingerprint_EyouEmail(t *testing.T) {
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"eyoumail", "eyouws"}, Condition: "and", CaseInsensitive: true},
		{Type: "word", Part: "body", Words: []string{"/tpl/login/user/images/dbg.png", "亿邮电子邮件系统"}, CaseInsensitive: true},
	}, "or")

	q := ops.ToQuery()
	for _, platform := range []string{"fofa", "hunter", "censys"} {
		r := q.Emit(platform)
		t.Logf("[%s] %s", platform, r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", platform)
		}
	}
}

func TestRealFingerprint_MixedMatchersCombined(t *testing.T) {
	m1 := &Matcher{Type: "word", Part: "body", Words: []string{"<title>Login</title>"}}
	m2 := &Matcher{Type: "status", Status: []int{200}}

	ops := compileOperators([]*Matcher{m1, m2}, "and")
	q := ops.ToQuery()

	tests := []struct {
		platform string
		expected string
	}{
		{"fofa", `body="<title>Login</title>" && status_code="200"`},
		{"hunter", `body="<title>Login</title>" && status_code="200"`},
		{"censys", `services.http.response.body: "<title>Login</title>" AND services.http.response.status_code: 200`},
	}

	for _, tt := range tests {
		t.Run(tt.platform, func(t *testing.T) {
			r := q.Emit(tt.platform)
			if r.Query != tt.expected {
				t.Errorf("got  %q\nwant %q", r.Query, tt.expected)
			}
		})
	}
}

func TestRealFingerprint_AllPlatformsComparison(t *testing.T) {
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"Powered by Discuz!"}, CaseInsensitive: true},
		{Type: "word", Part: "header", Words: []string{"x-powered-by: php"}, CaseInsensitive: true},
		{Type: "status", Status: []int{200}},
	}, "or")

	q := ops.ToQuery()
	fmt.Println("\n=== Discuz! fingerprint ===")
	for _, p := range []string{"fofa", "hunter", "censys"} {
		r := q.Emit(p)
		fmt.Printf("  %-8s %s\n", p+":", r.Query)
		if r.Query == "" {
			t.Errorf("[%s] empty query", p)
		}
	}
}

func TestRealFingerprint_RegexPartialResult(t *testing.T) {
	ops := compileOperators([]*Matcher{
		{Type: "word", Part: "body", Words: []string{"admin"}, CaseInsensitive: true},
		{Type: "regex", Regex: []string{`version\s+(\d+\.\d+)`}},
	}, "or")

	r := ops.ToQuery().ToFOFA()
	t.Logf("query=%q errors=%v", r.Query, r.Errors)
	if r.Query == "" {
		t.Error("expected partial query from word matcher")
	}
	if !r.HasErrors() {
		t.Error("expected errors from regex matcher")
	}
}
