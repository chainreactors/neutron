package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// startTokenServer records, per request path, the value of the ?token= query so
// tests can compare what each HTTP block actually sent.
func startTokenServer(t *testing.T) (*httptest.Server, *sync.Map) {
	t.Helper()
	var seen sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.URL.Path, r.URL.Query().Get("token"))
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func tokenFor(t *testing.T, seen *sync.Map, path string) string {
	t.Helper()
	v, ok := seen.Load(path)
	require.Truef(t, ok, "no request recorded for %s", path)
	return v.(string)
}

// TestPreprocessorInVariableStableAcrossBlocks is the badcase: a preprocessor
// used only inside a `variables:` definition (never directly in path/body/header)
// must resolve, and resolve to the SAME value across every HTTP block. The old
// runtime per-request scan missed it because randstr_probe never appeared in the
// request parts it scanned.
func TestPreprocessorInVariableStableAcrossBlocks(t *testing.T) {
	server, seen := startTokenServer(t)

	r1 := &Request{Path: []string{"{{BaseURL}}/a?token={{token}}"}, Method: "GET"}
	r2 := &Request{Path: []string{"{{BaseURL}}/b?token={{token}}"}, Method: "GET"}

	var variables protocols.Variable
	require.NoError(t, yaml.Unmarshal([]byte("token: '{{randstr_probe}}'"), &variables))

	options := &protocols.ExecuterOptions{
		Variables: variables,
		Options:   &protocols.Options{Timeout: 5},
	}
	exec := executer.NewExecuter([]protocols.Request{r1, r2}, options)
	require.NoError(t, exec.Compile())

	_, err := exec.Execute(protocols.NewScanContext(server.URL, nil))
	require.NoError(t, err)

	a := tokenFor(t, seen, "/a")
	b := tokenFor(t, seen, "/b")
	require.NotEmpty(t, a, "token must resolve, not be skipped as unresolved")
	require.NotContains(t, a, "randstr_probe", "preprocessor must be replaced, not sent literally")
	require.NotContains(t, a, "{{", "no unresolved template should reach the wire")
	require.Equal(t, a, b, "preprocessor-backed variable must be identical across blocks")
}

// TestBareRandstrStableAcrossBlocks covers a bare {{randstr}} in the request path
// (no variables block): it must resolve and stay identical across HTTP blocks,
// which is what the shared compile-time frozen map guarantees in place of the old
// per-request globalVars.
func TestBareRandstrStableAcrossBlocks(t *testing.T) {
	server, seen := startTokenServer(t)

	r1 := &Request{Path: []string{"{{BaseURL}}/a?token={{randstr}}"}, Method: "GET"}
	r2 := &Request{Path: []string{"{{BaseURL}}/b?token={{randstr}}"}, Method: "GET"}

	options := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
	exec := executer.NewExecuter([]protocols.Request{r1, r2}, options)
	require.NoError(t, exec.Compile())

	_, err := exec.Execute(protocols.NewScanContext(server.URL, nil))
	require.NoError(t, err)

	a := tokenFor(t, seen, "/a")
	b := tokenFor(t, seen, "/b")
	require.NotEmpty(t, a)
	require.NotContains(t, a, "{{")
	require.Equal(t, a, b, "bare {{randstr}} must be identical across blocks")
}
