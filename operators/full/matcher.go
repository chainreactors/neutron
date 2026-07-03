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
	operators.RegisterMatcherType("json", operators.JSONMatcher, compileJSONMatcher, matchJSON)
	operators.RegisterMatcherType("xpath", operators.XPathMatcher, nil, matchXPath)
}

func compileJSONMatcher(m *operators.Matcher) error {
	var compiled []*gojq.Code
	for _, query := range m.JSON {
		parsed, err := gojq.Parse(query)
		if err != nil {
			return fmt.Errorf("could not parse json matcher: %s", query)
		}
		code, err := gojq.Compile(parsed)
		if err != nil {
			return fmt.Errorf("could not compile json matcher: %s", query)
		}
		compiled = append(compiled, code)
	}
	m.SetCompiledData(compiled)
	return nil
}

func matchJSON(m *operators.Matcher, corpus string, _ map[string]interface{}) (bool, []operators.MatchHit) {
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(corpus), &jsonObj); err != nil {
		return false, nil
	}

	compiled, ok := m.GetCompiledData().([]*gojq.Code)
	if !ok {
		return false, nil
	}

	var matchedItems []operators.MatchHit
	for i, code := range compiled {
		iter := code.Run(jsonObj)
		v, ok := iter.Next()
		if !ok {
			if m.GetCondition() == operators.ANDCondition {
				return false, nil
			}
			continue
		}
		if _, isErr := v.(error); isErr {
			if m.GetCondition() == operators.ANDCondition {
				return false, nil
			}
			continue
		}

		if !isJQTruthy(v) {
			if m.GetCondition() == operators.ANDCondition {
				return false, nil
			}
			continue
		}

		result := common.ToString(v)
		rule := ""
		if i < len(m.JSON) {
			rule = m.JSON[i]
		}
		matchedItems = append(matchedItems, operators.MatchHit{Value: result, Rule: rule})

		if m.GetCondition() == operators.ORCondition && !m.MatchAll {
			return true, matchedItems
		}
		if len(compiled)-1 == i && !m.MatchAll {
			return true, matchedItems
		}
	}
	if len(matchedItems) > 0 && m.MatchAll {
		return true, matchedItems
	}
	return false, nil
}

func isJQTruthy(v interface{}) bool {
	switch val := v.(type) {
	case nil:
		return false
	case bool:
		return val
	case float64:
		return val != 0
	case string:
		return val != ""
	default:
		return true
	}
}

func matchXPath(m *operators.Matcher, corpus string, _ map[string]interface{}) (bool, []operators.MatchHit) {
	if strings.HasPrefix(corpus, "<?xml") {
		return matchXML(m, corpus)
	}
	return matchHTML(m, corpus)
}

func matchHTML(m *operators.Matcher, corpus string) (bool, []operators.MatchHit) {
	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return false, nil
	}

	var matchedItems []operators.MatchHit
	for i, xpath := range m.XPath {
		nodes, err := htmlquery.QueryAll(doc, xpath)
		if err != nil || len(nodes) == 0 {
			if m.GetCondition() == operators.ANDCondition {
				return false, nil
			}
			continue
		}

		for _, node := range nodes {
			matchedItems = append(matchedItems, operators.MatchHit{Value: htmlquery.InnerText(node), Rule: xpath})
		}

		if m.GetCondition() == operators.ORCondition && !m.MatchAll {
			return true, matchedItems
		}
		if len(m.XPath)-1 == i && !m.MatchAll {
			return true, matchedItems
		}
	}
	if len(matchedItems) > 0 && m.MatchAll {
		return true, matchedItems
	}
	return false, nil
}

func matchXML(m *operators.Matcher, corpus string) (bool, []operators.MatchHit) {
	doc, err := xmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return false, nil
	}

	var matchedItems []operators.MatchHit
	for i, xpath := range m.XPath {
		nodes, err := xmlquery.QueryAll(doc, xpath)
		if err != nil || len(nodes) == 0 {
			if m.GetCondition() == operators.ANDCondition {
				return false, nil
			}
			continue
		}

		for _, node := range nodes {
			matchedItems = append(matchedItems, operators.MatchHit{Value: node.InnerText(), Rule: xpath})
		}

		if m.GetCondition() == operators.ORCondition && !m.MatchAll {
			return true, matchedItems
		}
		if len(m.XPath)-1 == i && !m.MatchAll {
			return true, matchedItems
		}
	}
	if len(matchedItems) > 0 && m.MatchAll {
		return true, matchedItems
	}
	return false, nil
}
