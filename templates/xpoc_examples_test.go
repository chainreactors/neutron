package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainreactors/neutron/protocols"
	"github.com/stretchr/testify/require"
)

// TestXpocExamplesLoadAndCompile is a regression guard over a curated set of
// real xray fingerprints converted by the m09ic converter (the products we
// exercised in the xpoc <-> SDK/Neutron real-target comparison runs). It locks
// in that every converted example stays loadable and compilable under the
// current runtime: any change to the converter or protocol layer that breaks
// one of these templates fails CI here instead of silently in production.
//
// To refresh the corpus, drop more converted *.yaml into testdata/xpoc-examples.
// No code change is needed — the test discovers files at runtime.
func TestXpocExamplesLoadAndCompile(t *testing.T) {
	dir := filepath.Join("testdata", "xpoc-examples")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var yamls []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
			yamls = append(yamls, e.Name())
		}
	}
	require.NotEmpty(t, yamls, "no example templates found in %s", dir)

	for _, name := range yamls {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, err)

			tmpl, err := Load(data)
			require.NoErrorf(t, err, "load %s", name)

			options := &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}}
			require.NoErrorf(t, tmpl.Compile(options), "compile %s", name)
			require.Greaterf(t, tmpl.TotalRequests, 0, "%s compiled to zero requests", name)
		})
	}
}
