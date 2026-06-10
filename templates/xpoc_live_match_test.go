package templates

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
)

// TestXpocExamplesLiveMatch actually executes each curated example against one
// real, previously-verified target and asserts the template still MATCHES it.
// Unlike TestXpocExamplesLoadAndCompile (which only proves the YAML loads and
// compiles), this guards end-to-end runtime behavior: a converter or protocol
// regression that makes a working fingerprint stop hitting fails here.
//
// It is LIVE NETWORK and OPT-IN: skipped unless NEUTRON_LIVE_MATCH is set, so
// the default offline `go test` stays green. Targets are real third-party hosts
// recorded in testdata/xpoc-examples/live-targets.json; they may go offline or
// be unreachable from some networks (e.g. CN gov/corp sites from non-CN CI
// runners), which will surface here as a failure.
func TestXpocExamplesLiveMatch(t *testing.T) {
	if os.Getenv("NEUTRON_LIVE_MATCH") == "" {
		t.Skip("set NEUTRON_LIVE_MATCH=1 to run live-network match assertions")
	}
	dir := filepath.Join("testdata", "xpoc-examples")

	raw, err := os.ReadFile(filepath.Join(dir, "live-targets.json"))
	require.NoError(t, err)
	var targets map[string]struct {
		Product string `json:"product"`
		URL     string `json:"url"`
	}
	require.NoError(t, json.Unmarshal(raw, &targets))
	require.NotEmpty(t, targets)

	for stem, tgt := range targets {
		t.Run(stem, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, stem+".yaml"))
			require.NoError(t, err)

			tmpl, err := Load(data)
			require.NoError(t, err)
			require.NoError(t, tmpl.Compile(&protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 15}}))

			// Distinguish two failure modes: a network error (host down /
			// unreachable from this runner) is environmental and must NOT fail
			// the regression — only a reachable target that stops matching is a
			// real regression. Retry once to ride out a transient blip, then
			// skip on a persistent transport error and fail only on no-match.
			var res *operators.Result
			for attempt := 0; attempt < 2; attempt++ {
				res, err = tmpl.Execute(tgt.URL, nil)
				if err == nil {
					break
				}
			}
			if err != nil {
				t.Skipf("%s (%s) unreachable, skipping: %v", stem, tgt.Product, err)
			}
			require.NotNil(t, res)
			require.Truef(t, res.Matched, "%s (%s) reachable but did not match %s", stem, tgt.Product, tgt.URL)
		})
	}
}
