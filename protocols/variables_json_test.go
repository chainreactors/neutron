//go:build json
// +build json

package protocols

import (
	"testing"

	"github.com/chainreactors/neutron/common"
	"github.com/stretchr/testify/require"
)

func TestJSONStableValuesFreezesResolvedValueContainingParenthesis(t *testing.T) {
	vars := Variable{"r1": `{{rand_base(1, "(")}}`}
	frozen := vars.StableValues()

	require.Equal(t, "(", common.ToString(frozen["r1"]))
}

func TestJSONStableValuesKeepsRuntimeDependentVariableUnfrozen(t *testing.T) {
	vars := Variable{"token": `{{concat("accepted-", seed)}}`}
	frozen := vars.StableValues()

	require.NotContains(t, frozen, "token")
}

func TestJSONWithFrozenPinsFrozenKeysAndReevaluatesOthers(t *testing.T) {
	vars := Variable{
		"r1":    `{{concat("token-", rand_base(8, "abc"))}}`,
		"token": `{{Hostname}}`,
	}
	frozen := vars.StableValues()
	baked := vars.WithFrozen(frozen)

	first := baked.Evaluate(map[string]interface{}{"Hostname": "host-a"})
	second := baked.Evaluate(map[string]interface{}{"Hostname": "host-b"})

	require.Equal(t, first["r1"], second["r1"])
	require.Equal(t, "host-a", first["token"])
	require.Equal(t, "host-b", second["token"])
}
