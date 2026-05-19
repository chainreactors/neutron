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
	e := &dsl.FOFAEmitter{}
	m := newMatcher("word")
	m.Words = []string{"admin", "login"}
	m.condition = ANDCondition

	r := m.ToQuery(e)
	expected := `(body="admin" && body="login")`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherWordOrCondition(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("word")
	m.Words = []string{"login", "signin"}
	m.condition = ORCondition

	r := m.ToQuery(e)
	expected := `(body="login" || body="signin")`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherWordHeaderPart(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("word")
	m.Part = "header"
	m.Words = []string{"Apache"}
	m.condition = ORCondition

	r := m.ToQuery(e)
	expected := `header="Apache"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherStatus(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("status")
	m.Status = []int{200, 301}

	r := m.ToQuery(e)
	expected := `(status_code="200" || status_code="301")`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherFaviconFOFA(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("favicon")
	m.Hash = []string{"12345"}

	r := m.ToQuery(e)
	expected := `icon_hash="12345"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherFaviconCensys(t *testing.T) {
	e := &dsl.CensysEmitter{}
	m := newMatcher("favicon")
	m.Hash = []string{"12345"}

	r := m.ToQuery(e)
	if r.Query != "" {
		t.Errorf("expected empty query for censys favicon, got %q", r.Query)
	}
	if !r.HasErrors() {
		t.Error("expected error for censys favicon")
	}
}

func TestMatcherDSL(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("dsl")
	m.DSL = []string{`contains(body, "wp-content") && status_code == 200`}
	m.condition = ORCondition

	r := m.ToQuery(e)
	expected := `body="wp-content" && status_code="200"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherNegative(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("word")
	m.Words = []string{"error"}
	m.Negative = true
	m.condition = ORCondition

	r := m.ToQuery(e)
	expected := `!(body="error")`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestMatcherRegexError(t *testing.T) {
	e := &dsl.FOFAEmitter{}
	m := newMatcher("regex")
	m.Regex = []string{"pattern"}

	r := m.ToQuery(e)
	if !r.HasErrors() {
		t.Error("expected error for regex matcher")
	}
}

func TestOperatorsToQuery(t *testing.T) {
	e := &dsl.FOFAEmitter{}

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

	r := ops.ToQuery(e)
	expected := `body="admin" && status_code="200"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestOperatorsOrCondition(t *testing.T) {
	e := &dsl.CensysEmitter{}

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

	r := ops.ToQuery(e)
	expected := `services.http.response.body: "login" OR services.http.response.headers: "nginx"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestOperatorsPartialResult(t *testing.T) {
	e := &dsl.FOFAEmitter{}

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

	r := ops.ToQuery(e)
	if r.Query != `body="test"` {
		t.Errorf("got %q, want partial query", r.Query)
	}
	if !r.HasErrors() {
		t.Error("expected errors for regex matcher")
	}
}
