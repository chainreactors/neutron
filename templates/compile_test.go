package templates

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/chainreactors/neutron/protocols/http"
	_ "github.com/chainreactors/neutron/protocols/network"

	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCompileRejectsNilHTTPRequest(t *testing.T) {
	yamlContent := `
id: nil-http-request
info:
  name: Nil HTTP Request
  severity: info
http:
  -
`

	var tmpl Template
	require.NoError(t, yaml.Unmarshal([]byte(yamlContent), &tmpl))

	err := tmpl.Compile(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "http request at index 0 is nil")
}

func TestCompileRejectsNilTemplate(t *testing.T) {
	var tmpl *Template
	err := tmpl.Compile(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "template is nil")
}

func TestCompileDoesNotShareTemplateVariablesThroughReusedOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first-path":
			fmt.Fprint(w, "first matched")
		case "/second-path":
			fmt.Fprint(w, "second matched")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, "unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	firstYAML := `
id: first-template
info:
  name: First Template
  severity: info
variables:
  pathname: first-path
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{pathname}}"
    matchers:
      - type: word
        words:
          - "first matched"
`
	secondYAML := `
id: second-template
info:
  name: Second Template
  severity: info
variables:
  other: second-path
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{other}}"
    matchers:
      - type: word
        words:
          - "second matched"
`
	var first, second Template
	require.NoError(t, yaml.Unmarshal([]byte(firstYAML), &first))
	require.NoError(t, yaml.Unmarshal([]byte(secondYAML), &second))

	options := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	require.NoError(t, first.Compile(options))
	require.NoError(t, second.Compile(options))
	require.Zero(t, options.Variables.Len())

	result, err := first.Execute(server.URL, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Matched)
	require.Contains(t, result.Request, "/first-path")
}
