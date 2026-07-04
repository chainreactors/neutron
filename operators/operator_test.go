package operators

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResultRequestResponseFields(t *testing.T) {
	t.Run("empty by default", func(t *testing.T) {
		result := &Result{}
		result.Matched = true
		require.Empty(t, result.Request)
		require.Empty(t, result.Response)
	})

	t.Run("stores raw HTTP strings", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"

		result := &Result{
			Request:  rawReq,
			Response: rawResp,
		}
		result.Matched = true

		require.Equal(t, rawReq, result.Request)
		require.Equal(t, rawResp, result.Response)
	})
}

func TestOperatorsCompileRejectsNilEntries(t *testing.T) {
	err := (&Operators{Matchers: []*Matcher{nil}}).Compile()
	require.Error(t, err)
	require.Contains(t, err.Error(), "matcher at index 0 is nil")

	err = (&Operators{Extractors: []*Extractor{nil}}).Compile()
	require.Error(t, err)
	require.Contains(t, err.Error(), "extractor at index 0 is nil")

	var ops *Operators
	err = ops.Compile()
	require.Error(t, err)
	require.Contains(t, err.Error(), "operators is nil")
}

func TestOperatorsExecute(t *testing.T) {
	t.Run("OR condition with word matcher", func(t *testing.T) {
		ops := &Operators{
			Matchers: []*Matcher{
				{
					Type:      "word",
					Words:     []string{"hello"},
					Condition: "or",
				},
			},
		}
		err := ops.Compile()
		require.NoError(t, err)

		mf := func(data map[string]interface{}, matcher *Matcher) (bool, []MatchHit) {
			return matcher.MatchWords("hello world", data)
		}
		ef := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return nil
		}

		result, ok := ops.Execute(map[string]interface{}{}, mf, ef)
		require.True(t, ok)
		require.NotNil(t, result)
		require.True(t, result.Matched)
	})

	t.Run("AND condition all match", func(t *testing.T) {
		ops := &Operators{
			MatchersCondition: "and",
			Matchers: []*Matcher{
				{Type: "word", Words: []string{"hello"}},
				{Type: "word", Words: []string{"world"}},
			},
		}
		err := ops.Compile()
		require.NoError(t, err)

		mf := func(data map[string]interface{}, matcher *Matcher) (bool, []MatchHit) {
			return matcher.MatchWords("hello world", data)
		}
		ef := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return nil
		}

		result, ok := ops.Execute(map[string]interface{}{}, mf, ef)
		require.True(t, ok)
		require.NotNil(t, result)
		require.True(t, result.Matched)
	})

	t.Run("AND condition partial match fails", func(t *testing.T) {
		ops := &Operators{
			MatchersCondition: "and",
			Matchers: []*Matcher{
				{Type: "word", Words: []string{"hello"}},
				{Type: "word", Words: []string{"missing"}},
			},
		}
		err := ops.Compile()
		require.NoError(t, err)

		mf := func(data map[string]interface{}, matcher *Matcher) (bool, []MatchHit) {
			return matcher.MatchWords("hello world", data)
		}
		ef := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return nil
		}

		result, ok := ops.Execute(map[string]interface{}{}, mf, ef)
		require.False(t, ok)
		require.Nil(t, result)
	})

	t.Run("regex extractor", func(t *testing.T) {
		ops := &Operators{
			Extractors: []*Extractor{
				{
					Type:  "regex",
					Regex: []string{`version: (\d+\.\d+)`},
					Name:  "version",
				},
			},
		}
		err := ops.Compile()
		require.NoError(t, err)

		mf := func(data map[string]interface{}, matcher *Matcher) (bool, []MatchHit) {
			return false, nil
		}
		ef := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return extractor.ExtractRegex("version: 1.2")
		}

		result, ok := ops.Execute(map[string]interface{}{}, mf, ef)
		require.True(t, ok)
		require.NotNil(t, result)
		require.True(t, result.Extracted)
		require.Contains(t, result.ExtractsByName(), "version")
	})

	t.Run("internal extractor is gated by failed matcher", func(t *testing.T) {
		ops := &Operators{
			Matchers: []*Matcher{
				{Type: "word", Words: []string{"missing"}},
			},
			Extractors: []*Extractor{
				{
					Type:       "regex",
					Regex:      []string{`next=(/[a-z-]+)`},
					RegexGroup: 1,
					Name:       "next_path",
					Internal:   true,
				},
			},
		}
		err := ops.Compile()
		require.NoError(t, err)

		mf := func(data map[string]interface{}, matcher *Matcher) (bool, []MatchHit) {
			return matcher.MatchWords("next=/dynamic-login", data)
		}
		ef := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return extractor.ExtractRegex("next=/dynamic-login")
		}

		result, ok := ops.Execute(map[string]interface{}{}, mf, ef)
		require.False(t, ok)
		require.Nil(t, result)
	})
}

func TestMatcherDSLMissingVariablesAreNotDefaulted(t *testing.T) {
	t.Run("missing history variable fails the expression instead of masking it", func(t *testing.T) {
		matcher := &Matcher{
			Type: "dsl",
			DSL:  []string{`contains(location_3, "resource/anonym.jsp") || ((status_code_4 == 404) && contains(body_5, "CurrentUserId"))`},
		}
		require.NoError(t, matcher.CompileMatchers())

		ok := matcher.MatchDSL(map[string]interface{}{
			"status_code_4": 404,
			"body_5":        "CurrentUserId Com_Parameter StylePath",
		})
		require.False(t, ok)
	})

	t.Run("present history variable still matches", func(t *testing.T) {
		matcher := &Matcher{
			Type: "dsl",
			DSL:  []string{`contains(location_3, "resource/anonym.jsp")`},
		}
		require.NoError(t, matcher.CompileMatchers())
		require.True(t, matcher.MatchDSL(map[string]interface{}{
			"location_3": "/resource/anonym.jsp",
		}))
	})
}
