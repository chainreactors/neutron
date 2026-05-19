package operators

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResultRequestResponseFields(t *testing.T) {
	t.Run("empty by default", func(t *testing.T) {
		result := &Result{
			Matched: true,
		}
		require.Empty(t, result.Request)
		require.Empty(t, result.Response)
	})

	t.Run("stores raw HTTP strings", func(t *testing.T) {
		rawReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"

		result := &Result{
			Matched:  true,
			Request:  rawReq,
			Response: rawResp,
		}

		require.Equal(t, rawReq, result.Request)
		require.Equal(t, rawResp, result.Response)
	})
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

		matchFunc := func(data map[string]interface{}, matcher *Matcher) (bool, []string) {
			return matcher.MatchWords("hello world", data)
		}
		extractFunc := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return nil
		}

		result, ok := ops.Execute(map[string]interface{}{}, matchFunc, extractFunc)
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

		matchFunc := func(data map[string]interface{}, matcher *Matcher) (bool, []string) {
			return matcher.MatchWords("hello world", data)
		}
		extractFunc := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return nil
		}

		result, ok := ops.Execute(map[string]interface{}{}, matchFunc, extractFunc)
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

		matchFunc := func(data map[string]interface{}, matcher *Matcher) (bool, []string) {
			return matcher.MatchWords("hello world", data)
		}
		extractFunc := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return nil
		}

		result, ok := ops.Execute(map[string]interface{}{}, matchFunc, extractFunc)
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

		matchFunc := func(data map[string]interface{}, matcher *Matcher) (bool, []string) {
			return false, nil
		}
		extractFunc := func(data map[string]interface{}, extractor *Extractor) map[string]struct{} {
			return extractor.ExtractRegex("version: 1.2")
		}

		result, ok := ops.Execute(map[string]interface{}{}, matchFunc, extractFunc)
		require.True(t, ok)
		require.NotNil(t, result)
		require.True(t, result.Extracted)
		require.Contains(t, result.Extracts, "version")
	})
}
