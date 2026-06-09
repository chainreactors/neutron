package templates

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	protohttp "github.com/chainreactors/neutron/protocols/http"
)

func makeTemplate(id string, matchers []*operators.Matcher, matchersCond string, metadata map[string]interface{}) *Template {
	req := &protohttp.Request{}
	req.Operators = operators.Operators{
		Matchers:          matchers,
		MatchersCondition: matchersCond,
	}
	options := &protocols.ExecuterOptions{Options: &protocols.Options{}}
	req.Compile(options)

	t := &Template{
		Id:             id,
		Info:           Info{Name: id, Metadata: metadata},
		parsedRequests: []protocols.Request{req},
	}
	t.Executor = executer.NewExecuter(t.parsedRequests, options)
	return t
}

func TestTemplateToQuery_MetadataOnly(t *testing.T) {
	tmpl := makeTemplate("test-app", nil, "", map[string]interface{}{
		"fofa-query": []interface{}{`title="appspace"`},
	})

	r := tmpl.ToQuery().ToFOFA()
	if r.Query != `title="appspace"` {
		t.Errorf("got %q, want %q", r.Query, `title="appspace"`)
	}
}

func TestTemplateToQuery_MetadataMultipleQueries(t *testing.T) {
	tmpl := makeTemplate("test-multi", nil, "", map[string]interface{}{
		"fofa-query": []interface{}{`body="admin"`, `title="login"`},
	})

	r := tmpl.ToQuery().ToFOFA()
	expected := `body="admin" || title="login"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_FallbackToMatcher(t *testing.T) {
	tmpl := makeTemplate("test-fallback",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"wp-content"}},
		}, "or", nil)

	r := tmpl.ToQuery().ToFOFA()
	if r.Query != `body="wp-content"` {
		t.Errorf("got %q", r.Query)
	}
}

func TestTemplateToQuery_CombinedMetadataAndMatcher(t *testing.T) {
	tmpl := makeTemplate("test-combined",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"some-word"}},
		}, "or",
		map[string]interface{}{
			"fofa-query": `app="special-app"`,
		})

	r := tmpl.ToQuery().ToFOFA()
	expected := `app="special-app" || body="some-word"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_HunterQuery(t *testing.T) {
	tmpl := makeTemplate("test-hunter", nil, "", map[string]interface{}{
		"hunter-query": []interface{}{`app.name="connectwise screenconnect software"`},
	})

	r := tmpl.ToQuery().ToHunter()
	if r.Query != `app.name="connectwise screenconnect software"` {
		t.Errorf("got %q", r.Query)
	}
}

func TestTemplateToQuery_CensysFallback(t *testing.T) {
	tmpl := makeTemplate("test-censys",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"admin"}},
			{Type: "status", Status: []int{200}},
		}, "and", nil)

	r := tmpl.ToQuery().ToCensys()
	expected := `services.http.response.body: "admin" AND services.http.response.status_code: 200`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_AllPlatformsFromOneQuery(t *testing.T) {
	tmpl := makeTemplate("test-all",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"test"}},
		}, "or", nil)

	q := tmpl.ToQuery()
	fofa := q.ToFOFA()
	hunter := q.ToHunter()
	censys := q.ToCensys()

	if fofa.Query != `body="test"` {
		t.Errorf("fofa: got %q", fofa.Query)
	}
	if hunter.Query != `body="test"` {
		t.Errorf("hunter: got %q", hunter.Query)
	}
	if censys.Query != `services.http.response.body: "test"` {
		t.Errorf("censys: got %q", censys.Query)
	}
}

func TestTemplateToQuery_MetadataPlatformIsolation(t *testing.T) {
	tmpl := makeTemplate("test-isolation", nil, "", map[string]interface{}{
		"fofa-query":   `app="WordPress"`,
		"hunter-query": `app.name="WordPress"`,
	})

	q := tmpl.ToQuery()

	fofa := q.ToFOFA()
	if fofa.Query != `app="WordPress"` {
		t.Errorf("fofa got %q", fofa.Query)
	}

	hunter := q.ToHunter()
	if hunter.Query != `app.name="WordPress"` {
		t.Errorf("hunter got %q", hunter.Query)
	}

	censys := q.ToCensys()
	if censys.Query != "" {
		t.Errorf("censys should be empty (no censys metadata, no matchers), got %q", censys.Query)
	}
}
