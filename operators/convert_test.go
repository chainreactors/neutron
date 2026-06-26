package operators

import (
	"fmt"
	"testing"

	"github.com/chainreactors/neutron/common/dsl"
)

func newMatcher(typ string) *Matcher {
	m := &Matcher{Type: typ, Part: "body"}
	m.matcherType = matcherTypes[typ]
	return m
}

func TestMatcherWordToQuery(t *testing.T) {
	m := newMatcher("word")
	m.Words = []string{"admin", "login"}
	m.condition = ANDCondition

	r := m.ToQuery().ToFOFA()
	expected := `body="admin" && body="login"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherWordOrCondition(t *testing.T) {
	m := newMatcher("word")
	m.Words = []string{"login", "signin"}
	m.condition = ORCondition

	r := m.ToQuery().ToFOFA()
	expected := `body="login" || body="signin"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherWordHeaderPart(t *testing.T) {
	m := newMatcher("word")
	m.Part = "header"
	m.Words = []string{"Apache"}
	m.condition = ORCondition

	r := m.ToQuery().ToFOFA()
	expected := `header="Apache"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherStatus(t *testing.T) {
	m := newMatcher("status")
	m.Status = []int{200, 301}

	r := m.ToQuery().ToFOFA()
	expected := `status_code="200" || status_code="301"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherFaviconFOFA(t *testing.T) {
	m := newMatcher("favicon")
	m.Hash = []string{"12345"}

	r := m.ToQuery().ToFOFA()
	expected := `icon_hash="12345"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherFaviconCensys(t *testing.T) {
	m := newMatcher("favicon")
	m.Hash = []string{"12345"}

	r := m.ToQuery().ToCensys()
	if r.Query != "" {
		t.Errorf("expected empty query for censys favicon, got %q", r.Query)
	}
	if !r.HasErrors() {
		t.Error("expected error for censys favicon")
	}
}

func TestMatcherDSL(t *testing.T) {
	m := newMatcher("dsl")
	m.DSL = []string{`contains(body, "wp-content") && status_code == 200`}
	m.condition = ORCondition

	r := m.ToQuery().ToFOFA()
	expected := `body="wp-content" && status_code="200"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherNegative(t *testing.T) {
	m := newMatcher("word")
	m.Words = []string{"error"}
	m.Negative = true
	m.condition = ORCondition

	r := m.ToQuery().ToFOFA()
	expected := `!(body="error")`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherRegexError(t *testing.T) {
	m := newMatcher("regex")
	m.Regex = []string{"pattern"}

	q := m.ToQuery()
	if len(q.Errors) == 0 {
		t.Error("expected error for regex matcher")
	}
}

func TestOperatorsToQuery(t *testing.T) {
	wordMatcher := newMatcher("word")
	wordMatcher.Words = []string{"admin"}
	wordMatcher.condition = ORCondition

	statusMatcher := newMatcher("status")
	statusMatcher.Status = []int{200}

	ops := &Operators{
		Matchers:          []*Matcher{wordMatcher, statusMatcher},
		MatchersCondition: "and",
	}
	ops.matchersCondition = ANDCondition

	r := ops.ToQuery().ToFOFA()
	expected := `body="admin" && status_code="200"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestOperatorsOrCondition(t *testing.T) {
	m1 := newMatcher("word")
	m1.Words = []string{"login"}
	m1.condition = ORCondition

	m2 := newMatcher("word")
	m2.Part = "header"
	m2.Words = []string{"nginx"}
	m2.condition = ORCondition

	ops := &Operators{
		Matchers: []*Matcher{m1, m2},
	}
	ops.matchersCondition = ORCondition

	r := ops.ToQuery().ToCensys()
	expected := `services.http.response.body: "login" OR services.http.response.headers: "nginx"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestOperatorsPartialResult(t *testing.T) {
	wordMatcher := newMatcher("word")
	wordMatcher.Words = []string{"test"}
	wordMatcher.condition = ORCondition

	regexMatcher := newMatcher("regex")
	regexMatcher.Regex = []string{"pattern"}

	ops := &Operators{
		Matchers:          []*Matcher{wordMatcher, regexMatcher},
		MatchersCondition: "and",
	}
	ops.matchersCondition = ANDCondition

	r := ops.ToQuery().ToFOFA()
	if r.Query != `body="test"` {
		t.Errorf("got %q, want partial query", r.Query)
	}
	if !r.HasErrors() {
		t.Error("expected errors for regex matcher")
	}
}

func TestQueryAllPlatforms(t *testing.T) {
	m := newMatcher("word")
	m.Words = []string{"admin"}
	m.condition = ORCondition

	q := m.ToQuery()

	tests := []struct {
		name string
		r    *dsl.Result
		want string
	}{
		{"fofa", q.ToFOFA(), `body="admin"`},
		{"hunter", q.ToHunter(), `body="admin"`},
		{"censys", q.ToCensys(), `services.http.response.body: "admin"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.r.Query != tt.want {
				t.Errorf("got %q, want %q", tt.r.Query, tt.want)
			}
		})
	}
}

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
