package templates

import (
	"fmt"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"gopkg.in/yaml.v3"
)

// Classification contains the vulnerability classification data for a template.
type Classification struct {
	// CVE ID for the template
	CVEID string `json:"cve-id,omitempty" yaml:"cve-id,omitempty"`
	// CWE ID for the template
	CWEID string `json:"cwe-id,omitempty" yaml:"cwe-id,omitempty"`
	// CVSS Metrics for the template
	CVSSMetrics string `json:"cvss-metrics,omitempty" yaml:"cvss-metrics,omitempty"`
	// CVSS Score for the template
	CVSSScore float64 `json:"cvss-score,omitempty" yaml:"cvss-score,omitempty"`
	// EPSS Score for the template
	EPSSScore float64 `json:"epss-score,omitempty" yaml:"epss-score,omitempty"`
	// EPSS Percentile for the template
	EPSSPercentile float64 `json:"epss-percentile,omitempty" yaml:"epss-percentile,omitempty"`
	// CPE for the template
	CPE string `json:"cpe,omitempty" yaml:"cpe,omitempty"`
}

// Info contains metadata information about a template
type Info struct {
	// Name should be good short summary that identifies what the template does
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Author of the template. Multiple values can also be specified separated by commas
	Author string `json:"author,omitempty" yaml:"author,omitempty"`
	// Any tags for the template. Multiple values can also be specified separated by commas
	Tags string `json:"tags,omitempty" yaml:"tags,omitempty"`
	// Description of the template. You can go in-depth here on what the template actually does
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Impact of the template. You can go in-depth here on impact of the template
	Impact string `json:"impact,omitempty" yaml:"impact,omitempty"`
	// References for the template. This should contain links relevant to the template
	Reference []string `json:"reference,omitempty" yaml:"reference,omitempty"`
	// Severity of the template
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	// Metadata of the template
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	// Classification contains classification information about the template
	Classification *Classification `json:"classification,omitempty" yaml:"classification,omitempty"`
	// Remediation steps for the template. You can go in-depth here on how to mitigate the problem found by this template
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	// Zombie field for compatibility
	Zombie string `json:"zombie,omitempty" yaml:"zombie,omitempty"`
}

type rawProtocolEntry struct {
	key  string
	node *yaml.Node
}

type Template struct {
	// ID is the unique id for the template.
	Id string `json:"id" yaml:"id"`

	// Fingers contains fingerprinting rules for the template
	Fingers []string `json:"finger,omitempty" yaml:"finger,omitempty"`

	// Chains contains chaining rules for the template
	Chains []string `json:"chain,omitempty" yaml:"chain,omitempty"`

	// Opsec specifies if the template should be executed in opsec mode
	Opsec bool `json:"opsec,omitempty" yaml:"opsec,omitempty"`

	// Info contains metadata information about the template
	Info Info `json:"info" yaml:"info"`

	// Variables contains any variables for the current template
	Variables protocols.Variable `yaml:"variables,omitempty" json:"variables,omitempty"`

	// rawProtocols stores unparsed YAML nodes for registered protocol keys,
	// preserving YAML key order for deterministic request sequencing.
	rawProtocols []rawProtocolEntry

	// parsedRequests holds the deserialized protocol requests, populated by
	// Parse() or Compile(). Accessible via GetRequests().
	parsedRequests []protocols.Request

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executor is the actual template executor for running template requests
	Executor *executer.Executer `yaml:"-" json:"-"`
}

// knownFields lists Template field YAML keys that are NOT protocol blocks.
var knownFields = map[string]bool{
	"id": true, "finger": true, "chain": true, "opsec": true,
	"info": true, "variables": true,
}

func (t *Template) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node for template")
	}

	t.rawProtocols = nil

	// Split YAML content into known fields and protocol blocks.
	filteredContent := make([]*yaml.Node, 0, len(value.Content))
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		val := value.Content[i+1]
		if protocols.IsRegisteredProtocol(key) {
			t.rawProtocols = append(t.rawProtocols, rawProtocolEntry{key: key, node: val})
		} else {
			filteredContent = append(filteredContent, value.Content[i], val)
		}
	}

	filtered := *value
	filtered.Content = filteredContent

	type templateAlias Template
	return filtered.Decode((*templateAlias)(t))
}

// Parse deserializes the raw protocol YAML blocks into Request objects without
// compiling them. Compile() calls Parse() internally; call Parse() directly
// only when you need access to requests before compilation.
func (t *Template) Parse() error {
	t.parsedRequests = nil
	for _, entry := range t.rawProtocols {
		parsed, err := protocols.ParseProtocolRequests(entry.key, entry.node)
		if err != nil {
			return fmt.Errorf("parse %s protocol: %w", entry.key, err)
		}
		for i, req := range parsed {
			if req == nil {
				return fmt.Errorf("%s request at index %d is nil", entry.key, i)
			}
		}
		t.parsedRequests = append(t.parsedRequests, parsed...)
	}
	return nil
}

// GetRequests returns the parsed protocol requests. Available after Parse() or
// Compile(). The concrete types depend on which protocol packages are imported.
func (t *Template) GetRequests() []protocols.Request {
	return t.parsedRequests
}

// GetOperators returns the compiled operators from all protocol requests.
func (t *Template) GetOperators() []*operators.Operators {
	if t.Executor == nil {
		return nil
	}
	return t.Executor.GetCompiledOperators()
}
