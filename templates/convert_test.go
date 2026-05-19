package templates

import (
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/http"
)

func makeTemplate(id string, matchers []*operators.Matcher, matchersCond string, metadata map[string]interface{}) *Template {
	req := &http.Request{}
	req.Operators = operators.Operators{
		Matchers:          matchers,
		MatchersCondition: matchersCond,
	}
	req.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{}})

	t := &Template{
		Id:           id,
		Info:         Info{Name: id, Metadata: metadata},
		RequestsHTTP: []*http.Request{req},
	}
	return t
}

func TestTemplateToQuery_MetadataOnly(t *testing.T) {
	// Template with fofa-query but no matchers — metadata only
	tmpl := makeTemplate("test-app", nil, "", map[string]interface{}{
		"fofa-query": []interface{}{`title="appspace"`},
	})

	r := tmpl.ToQuery("fofa")
	if r.Source != "metadata" {
		t.Errorf("expected source=metadata, got %s", r.Source)
	}
	if r.Query != `title="appspace"` {
		t.Errorf("got %q, want %q", r.Query, `title="appspace"`)
	}
	t.Logf("[fofa] source=%s query=%s", r.Source, r.Query)
}

func TestTemplateToQuery_MetadataMultipleQueries(t *testing.T) {
	tmpl := makeTemplate("test-multi", nil, "", map[string]interface{}{
		"fofa-query": []interface{}{`body="admin"`, `title="login"`},
	})

	r := tmpl.ToQuery("fofa")
	expected := `body="admin" || title="login"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_MetadataString(t *testing.T) {
	tmpl := makeTemplate("test-str", nil, "", map[string]interface{}{
		"fofa-query": `server="nginx"`,
	})

	r := tmpl.ToQuery("fofa")
	if r.Query != `server="nginx"` {
		t.Errorf("got %q", r.Query)
	}
	if r.Source != "metadata" {
		t.Errorf("expected source=metadata")
	}
}

func TestTemplateToQuery_FallbackToMatcher(t *testing.T) {
	// No metadata query — should fall back to matcher conversion
	tmpl := makeTemplate("test-fallback",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"wp-content"}},
		}, "or", nil)

	r := tmpl.ToQuery("fofa")
	if r.Source != "matcher" {
		t.Errorf("expected source=matcher, got %s", r.Source)
	}
	if r.Query != `body="wp-content"` {
		t.Errorf("got %q", r.Query)
	}
	t.Logf("[fofa] source=%s query=%s", r.Source, r.Query)
}

func TestTemplateToQuery_CombinedMetadataAndMatcher(t *testing.T) {
	// Has both metadata query AND matchers — combined with OR
	tmpl := makeTemplate("test-combined",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"some-word"}},
		}, "or",
		map[string]interface{}{
			"fofa-query": `app="special-app"`,
		})

	r := tmpl.ToQuery("fofa")
	if r.Source != "combined" {
		t.Errorf("expected source=combined, got %s", r.Source)
	}
	expected := `app="special-app" || body="some-word"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_HunterQuery(t *testing.T) {
	tmpl := makeTemplate("test-hunter", nil, "", map[string]interface{}{
		"hunter-query": []interface{}{`app.name="connectwise screenconnect software"`},
	})

	r := tmpl.ToQuery("hunter")
	if r.Query != `app.name="connectwise screenconnect software"` {
		t.Errorf("got %q", r.Query)
	}
}

func TestTemplateToQuery_ShodanQuery(t *testing.T) {
	tmpl := makeTemplate("test-shodan", nil, "", map[string]interface{}{
		"shodan-query": []interface{}{`http.title:"admin"`, `http.html:"login"`},
	})

	r := tmpl.ToQuery("shodan")
	expected := `http.title:"admin" || http.html:"login"`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_CensysFallback(t *testing.T) {
	tmpl := makeTemplate("test-censys",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"admin"}},
			{Type: "status", Status: []int{200}},
		}, "and", nil)

	r := tmpl.ToQuery("censys")
	expected := `services.http.response.body: "admin" AND services.http.response.status_code: 200`
	if r.Query != expected {
		t.Errorf("got %q, want %q", r.Query, expected)
	}
}

func TestTemplateToQuery_EmptyMetadata(t *testing.T) {
	// Empty metadata query should fall back to matcher
	tmpl := makeTemplate("test-empty-meta",
		[]*operators.Matcher{
			{Type: "word", Part: "body", Words: []string{"test"}},
		}, "or",
		map[string]interface{}{
			"fofa-query": []interface{}{},
		})

	r := tmpl.ToQuery("fofa")
	if r.Source != "matcher" {
		t.Errorf("expected fallback to matcher for empty metadata, got %s", r.Source)
	}
}

func TestTemplateToQuery_UnknownPlatform(t *testing.T) {
	tmpl := makeTemplate("test-unknown", nil, "", nil)
	r := tmpl.ToQuery("nonexistent")
	if !r.HasErrors() {
		t.Error("expected error for unknown platform")
	}
}
