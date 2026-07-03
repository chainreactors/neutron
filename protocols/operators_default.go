package protocols

import (
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
)

// PartResolver maps a matcher/extractor `part:` to the string the operator
// should run against. Returns ("", false) when the part is absent — the dispatch
// loop treats that as a miss for everything except DSL (which works off the full
// data map).
//
// Each protocol owns this function because part semantics are protocol-specific:
//   - ssl folds `body` and `all` into `response` for xray-converter compatibility
//   - http would resolve `all_headers` / `favicon` to dedicated fields
//   - the default (DefaultPartResolver below) just looks `part` up in data
//     with empty falling back to `response`, matching nuclei's simple protocols
type PartResolver func(part string) (string, bool)

// DefaultPartResolver is the zero-special-case resolver used by protocols whose
// match part is a straight key into the event map, defaulting to `response` —
// matching nuclei's protocols.MakeDefaultMatchFunc behaviour exactly.
func DefaultPartResolver(data map[string]interface{}) PartResolver {
	return func(part string) (string, bool) {
		if part == "" {
			part = "response"
		}
		item, ok := data[part]
		if !ok {
			return "", false
		}
		return common.ToString(item), true
	}
}

// MakeDefaultMatchFunc is the shared matcher dispatch. It mirrors nuclei's
// protocols.MakeDefaultMatchFunc: every matcher type — including json / xpath —
// flows through one matrix, so a protocol can never silently drop a type by
// forgetting a switch case. json and xpath reach gojq / htmlquery through
// MatchWithHandler (the operators/full submodule); with no handler registered
// they no-op, exactly like nuclei's stdlib build.
//
// partResolver decouples "where does this part live in the event?" (protocol-
// specific) from "how do I run this matcher type?" (universal), so a protocol
// with a custom part scheme (ssl's body/all→response fold) doesn't have to
// duplicate the type-switch.
func MakeDefaultMatchFunc(data map[string]interface{}, matcher *operators.Matcher, partResolver PartResolver) (bool, []operators.MatchHit) {
	if matcher.GetType() == operators.DSLMatcher {
		return matcher.Result(matcher.MatchDSL(data)), nil
	}
	itemStr, ok := partResolver(matcher.Part)
	if !ok {
		return false, nil
	}
	switch matcher.GetType() {
	case operators.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr))), nil
	case operators.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(itemStr, data))
	case operators.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(itemStr))
	case operators.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(itemStr))
	default:
		// json / xpath (and any future registered matcher type) dispatch through
		// the registered handler — same fall-through nuclei uses.
		return matcher.ResultWithMatchedSnippet(matcher.MatchWithHandler(itemStr, data))
	}
}

// MakeDefaultExtractFunc is the extractor counterpart, mirroring nuclei's
// protocols.MakeDefaultExtractFunc. json / xpath reach the registered handler
// via ExtractWithHandler. partResolver carries the same protocol-specific part
// semantics as in MakeDefaultMatchFunc.
func MakeDefaultExtractFunc(data map[string]interface{}, extractor *operators.Extractor, partResolver PartResolver) map[string]struct{} {
	itemStr, ok := partResolver(extractor.Part)
	if !ok && extractor.GetType() != operators.DSLExtractor {
		return nil
	}
	switch extractor.GetType() {
	case operators.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case operators.KValExtractor:
		return extractor.ExtractKval(data)
	case operators.DSLExtractor:
		return extractor.ExtractDSL(data)
	default:
		// json / xpath (and any future registered extractor type) dispatch
		// through the registered handler against the resolved part string.
		return extractor.ExtractWithHandler(itemStr, data)
	}
}
