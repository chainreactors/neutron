package templates

import (
	"testing"

	"github.com/chainreactors/neutron/protocols/network"
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
	require.Len(t, tmpl.RequestsHTTP, 1)
	require.Nil(t, tmpl.RequestsHTTP[0])

	err := tmpl.Compile(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "http request at index 0 is nil")
}

func TestCompileRejectsNilTemplateAndNetworkRequest(t *testing.T) {
	var tmpl *Template
	err := tmpl.Compile(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "template is nil")

	tmpl = &Template{RequestsNetwork: []*network.Request{nil}}
	err = tmpl.Compile(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "network request at index 0 is nil")
}
