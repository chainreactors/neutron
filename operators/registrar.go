package operators

type ExtractFunc func(e *Extractor, corpus string, data map[string]interface{}) map[string]struct{}

type CompileExtractFunc func(e *Extractor) error

type MatchFunc func(m *Matcher, corpus string, data map[string]interface{}) (bool, []MatchHit)

type CompileMatchFunc func(m *Matcher) error

var (
	registeredExtractCompilers = map[ExtractorType]CompileExtractFunc{}
	registeredExtractHandlers  = map[ExtractorType]ExtractFunc{}
	registeredMatchCompilers   = map[MatcherType]CompileMatchFunc{}
	registeredMatchHandlers    = map[MatcherType]MatchFunc{}
)

func RegisterExtractorType(name string, typ ExtractorType, compile CompileExtractFunc, extract ExtractFunc) {
	extractorMappings[name] = typ
	if compile != nil {
		registeredExtractCompilers[typ] = compile
	}
	if extract != nil {
		registeredExtractHandlers[typ] = extract
	}
}

func RegisterMatcherType(name string, typ MatcherType, compile CompileMatchFunc, match MatchFunc) {
	matcherTypes[name] = typ
	if compile != nil {
		registeredMatchCompilers[typ] = compile
	}
	if match != nil {
		registeredMatchHandlers[typ] = match
	}
}
