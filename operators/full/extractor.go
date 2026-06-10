// Package full is the optional gojq + antchfx/htmlquery + antchfx/xmlquery
// backend for neutron's `json` and `xpath` extractor / matcher types.
//
// The main neutron module is intentionally go 1.11 + stdlib-only and does NOT
// register handlers for `json` / `xpath` — a template that uses them fails at
// CompileExtractors / CompileMatchers with "unknown extractor type: json" until
// this submodule is imported for side-effects:
//
//	import _ "github.com/chainreactors/neutron/operators/full"
//
// The blank-import is enough — init() below calls operators.RegisterExtractorType
// and operators.RegisterMatcherType, plugging gojq / xpath handlers into the
// dispatch maps the main module already exposes. Same pattern as common/tlsx/full.
//
// This submodule lives in its own Go module (operators/full/go.mod) so its
// dependency closure (gojq, htmlquery, xmlquery, antchfx/xpath, golang.org/x/{net,text})
// only lands in binaries that explicitly opt in. Scanner binaries that need
// nuclei-equivalent json/xpath support add a require + replace for
// `.../operators/full` alongside the existing neutron require.
package full

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/itchyny/gojq"
)

func init() {
	operators.RegisterExtractorType("json", operators.JSONExtractor, compileJSONExtractor, extractJSON)
	operators.RegisterExtractorType("xpath", operators.XPathExtractor, nil, extractXPath)
}

func compileJSONExtractor(e *operators.Extractor) error {
	var compiled []*gojq.Code
	for _, query := range e.JSON {
		parsed, err := gojq.Parse(query)
		if err != nil {
			return fmt.Errorf("could not parse json: %s", query)
		}
		code, err := gojq.Compile(parsed)
		if err != nil {
			return fmt.Errorf("could not compile json: %s", query)
		}
		compiled = append(compiled, code)
	}
	e.SetCompiledData(compiled)
	return nil
}

func extractJSON(e *operators.Extractor, corpus string, _ map[string]interface{}) map[string]struct{} {
	results := make(map[string]struct{})

	var jsonObj interface{}
	if err := json.Unmarshal([]byte(corpus), &jsonObj); err != nil {
		return results
	}

	compiled, ok := e.GetCompiledData().([]*gojq.Code)
	if !ok {
		return results
	}
	for _, k := range compiled {
		iter := k.Run(jsonObj)
		for {
			v, ok := iter.Next()
			if !ok {
				break
			}
			if _, ok := v.(error); ok {
				break
			}
			var result string
			if res, err := common.JSONScalarToString(v); err == nil {
				result = res
			} else if res, err := json.Marshal(v); err == nil {
				result = string(res)
			} else {
				result = common.ToString(v)
			}
			if _, ok := results[result]; !ok {
				results[result] = struct{}{}
			}
		}
	}
	return results
}

func extractXPath(e *operators.Extractor, corpus string, _ map[string]interface{}) map[string]struct{} {
	if strings.HasPrefix(corpus, "<?xml") {
		return extractXML(e, corpus)
	}
	return extractHTML(e, corpus)
}

func extractHTML(e *operators.Extractor, corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return results
	}
	for _, k := range e.XPath {
		nodes, err := htmlquery.QueryAll(doc, k)
		if err != nil {
			continue
		}
		for _, node := range nodes {
			var value string
			if e.Attribute != "" {
				value = htmlquery.SelectAttr(node, e.Attribute)
			} else {
				value = htmlquery.InnerText(node)
			}
			if _, ok := results[value]; !ok {
				results[value] = struct{}{}
			}
		}
	}
	return results
}

func extractXML(e *operators.Extractor, corpus string) map[string]struct{} {
	results := make(map[string]struct{})

	doc, err := xmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return results
	}
	for _, k := range e.XPath {
		nodes, err := xmlquery.QueryAll(doc, k)
		if err != nil {
			continue
		}
		for _, node := range nodes {
			var value string
			if e.Attribute != "" {
				value = node.SelectAttr(e.Attribute)
			} else {
				value = node.InnerText()
			}
			if _, ok := results[value]; !ok {
				results[value] = struct{}{}
			}
		}
	}
	return results
}
