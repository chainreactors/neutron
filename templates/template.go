package templates

import (
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/protocols/network"
	"github.com/chainreactors/neutron/protocols/ssl"
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

type Template struct {
	// ID is the unique id for the template.
	// A good ID uniquely identifies what the requests in the template are doing.
	Id string `json:"id" yaml:"id"`

	// Fingers contains fingerprinting rules for the template (neutron internal field)
	Fingers []string `json:"finger,omitempty" yaml:"finger,omitempty"`

	// Chains contains chaining rules for the template (neutron internal field)
	Chains []string `json:"chain,omitempty" yaml:"chain,omitempty"`

	// Opsec specifies if the template should be executed in opsec mode (neutron internal field)
	Opsec bool `json:"opsec,omitempty" yaml:"opsec,omitempty"`

	// Info contains metadata information about the template
	Info Info `json:"info" yaml:"info"`

	// Variables contains any variables for the current template
	Variables protocols.Variable `yaml:"variables,omitempty" json:"variables,omitempty"`

	// HTTP contains the http request to make in the template
	RequestsHTTP []*http.Request `json:"http,omitempty" yaml:"http,omitempty"`

	// Requests contains the http request to make in the template (legacy compatibility)
	// WARNING: 'requests' will be deprecated and will be removed in a future release. Please use 'http' instead.
	Requests []*http.Request `json:"requests,omitempty" yaml:"requests,omitempty"`

	// Network contains the network request to make in the template
	RequestsNetwork []*network.Request `json:"network,omitempty" yaml:"network,omitempty"`

	// SSL contains TLS certificate/handshake probes for nuclei-style ssl templates.
	RequestsSSL []*ssl.Request `json:"ssl,omitempty" yaml:"ssl,omitempty"`

	// TLS contains TLS certificate/handshake probes (alias for ssl).
	RequestsTLS []*ssl.Request `json:"tls,omitempty" yaml:"tls,omitempty"`

	// TCP contains the TCP network request to make in the template (alias for network)
	RequestsTCP []*network.Request `json:"tcp,omitempty" yaml:"tcp,omitempty"`

	// UDP contains the UDP network request to make in the template (alias for network)
	RequestsUDP []*network.Request `json:"udp,omitempty" yaml:"udp,omitempty"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executor is the actual template executor for running template requests
	Executor *executer.Executer `yaml:"-" json:"-"`
}

func (t *Template) GetRequests() []*http.Request {
	if len(t.RequestsHTTP) > 0 {
		return t.RequestsHTTP
	}
	if len(t.Requests) > 0 {
		return t.Requests
	}
	return nil
}
