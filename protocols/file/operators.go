package file

import (
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"time"
)

// Match matches a generic data response again a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *operators.Matcher) (bool, []string) {
	itemStr, _ := request.getMatchPart(matcher.Part, data)

	switch matcher.GetType() {
	case operators.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr))), []string{}
	case operators.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(itemStr, data))
	case operators.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(itemStr))
	case operators.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(itemStr))
	case operators.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	}
	return false, []string{}
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *operators.Extractor) map[string]struct{} {
	itemStr, _ := request.getMatchPart(extractor.Part, data)

	switch extractor.GetType() {
	case operators.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case operators.KValExtractor:
		return extractor.ExtractKval(data)
	case operators.DSLExtractor:
		return extractor.ExtractDSL(data)
	}
	return nil
}

func (request *Request) getMatchPart(part string, data protocols.InternalEvent) (string, bool) {
	switch part {
	case "body", "all", "data", "":
		part = "raw"
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}
	itemStr := common.ToString(item)

	return itemStr, true
}

// responseToDSLMap converts a file chunk elaboration to a map for use in DSL matching
func (request *Request) responseToDSLMap(raw, inputFilePath, matchedFileName string) protocols.InternalEvent {
	return protocols.InternalEvent{
		"path":    inputFilePath,
		"matched": matchedFileName,
		"raw":     raw,
		"type":    request.Type().String(),
		//"template-id":   request.options.TemplateID,
		//"template-info": request.options.TemplateInfo,
		//"template-path": request.options.TemplatePath,
	}
}

// MakeResultEvent creates a result event from internal wrapped event
// Deprecated: unused in stream mode, must be present for interface compatibility
//func (request *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
//	return protocols.MakeDefaultResultEvent(request, wrapped)
//}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

// MakeResultEventItem
// Deprecated: unused in stream mode, must be present for interface compatibility
func (request *Request) MakeResultEventItem(wrapped *protocols.InternalWrappedEvent) *protocols.ResultEvent {
	data := &protocols.ResultEvent{
		//MatcherStatus: true,
		TemplateID: common.ToString(wrapped.InternalEvent["template-id"]),
		//TemplatePath:     common.ToString(wrapped.InternalEvent["template-path"]),
		//Info:             wrapped.InternalEvent["template-info"].(model.Info),
		Type:             common.ToString(wrapped.InternalEvent["type"]),
		Path:             common.ToString(wrapped.InternalEvent["path"]),
		Matched:          common.ToString(wrapped.InternalEvent["matched"]),
		Host:             common.ToString(wrapped.InternalEvent["host"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		//Response:         common.ToString(wrapped.InternalEvent["raw"]),
		Timestamp: time.Now(),
	}
	return data
}
