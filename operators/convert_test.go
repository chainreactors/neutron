package operators

import (
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

func TestFaviconTypeUnsupported(t *testing.T) {
	m := &Matcher{Type: "favicon"}
	if err := m.CompileMatchers(); err == nil {
		t.Fatal("expected favicon matcher type to be unsupported")
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
