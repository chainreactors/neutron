package protocols

import (
	"regexp"
	"strings"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/common/dsl"
)

// preprocessorRE matches nuclei-style parse-time preprocessors such as
// {{randstr}}, {{randstr_xxx}}, {{randnum}} and {{randnum_xxx}}. A given token
// resolves to one stable value everywhere it appears within a compiled template.
var preprocessorRE = regexp.MustCompile(`\{\{\s*(randstr(?:_[A-Za-z0-9_]+)?|randnum(?:_[A-Za-z0-9_]+)?)\s*\}\}`)

// FrozenFor builds the single map of values frozen once for one execution. It
// folds together the two things that must stay stable across request blocks
// within a scan (but be regenerated between scans):
//
//   - the variables block's static/random results (Variable.StableValues), e.g.
//     rand_base() — so a multi-block template sees one value per scan;
//   - nuclei-style preprocessors ({{randstr}}/{{randnum}} and suffixed variants)
//     found in the variables definitions and in every request's parts — so bare
//     {{randstr}} and a variable like token: '{{randstr_probe}}' (which never
//     appears directly in a request) both resolve to one value per scan.
//
// Computed once in executer.Execute and only read afterwards; regenerating it
// per execution is what keeps randomness fresh between scans. Returns nil when
// there is nothing to freeze.
func FrozenFor(variables Variable, requests []Request) map[string]interface{} {
	frozen := variables.StableValues()
	if frozen == nil {
		frozen = make(map[string]interface{})
	}
	variables.ForEach(func(_ string, value interface{}) {
		seedPreprocessors(frozen, common.ToString(value))
	})
	for _, request := range requests {
		if request == nil {
			continue
		}
		seedPreprocessors(frozen, request.PreprocessorParts()...)
	}
	if len(frozen) == 0 {
		return nil
	}
	return frozen
}

// seedPreprocessors generates one stable value per unique preprocessor token
// found in parts, leaving already-seeded tokens untouched.
func seedPreprocessors(values map[string]interface{}, parts ...string) {
	for _, part := range parts {
		if part == "" {
			continue
		}
		for _, match := range preprocessorRE.FindAllStringSubmatch(part, -1) {
			if len(match) > 1 {
				ensurePreprocessor(values, match[1])
			}
		}
	}
}

func ensurePreprocessor(values map[string]interface{}, name string) {
	if _, ok := values[name]; ok {
		return
	}
	if strings.HasPrefix(name, "randnum") {
		values[name] = dsl.RandNum(4)
		return
	}
	values[name] = dsl.RandStr(8)
}
