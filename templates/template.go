package templates

import (
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/neutron/protocols/network"
)

// Classification contains the vulnerability classification data for a template.
type Classification struct {
	// CVE ID for the template
	CVEID string `json:"cve-id,omitempty" yaml:"cve-id,omitempty" jsonschema:"title=cve ids for the template,description=CVE IDs for the template,example=CVE-2020-14420"`
	// CWE ID for the template
	CWEID string `json:"cwe-id,omitempty" yaml:"cwe-id,omitempty" jsonschema:"title=cwe ids for the template,description=CWE IDs for the template,example=CWE-22"`
	// CVSS Metrics for the template
	CVSSMetrics string `json:"cvss-metrics,omitempty" yaml:"cvss-metrics,omitempty" jsonschema:"title=cvss metrics for the template,description=CVSS Metrics for the template,example=3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`
	// CVSS Score for the template
	CVSSScore float64 `json:"cvss-score,omitempty" yaml:"cvss-score,omitempty" jsonschema:"title=cvss score for the template,description=CVSS Score for the template,example=9.8"`
	// EPSS Score for the template
	EPSSScore float64 `json:"epss-score,omitempty" yaml:"epss-score,omitempty" jsonschema:"title=epss score for the template,description=EPSS Score for the template,example=0.42509"`
	// EPSS Percentile for the template
	EPSSPercentile float64 `json:"epss-percentile,omitempty" yaml:"epss-percentile,omitempty" jsonschema:"title=epss percentile for the template,description=EPSS Percentile for the template,example=0.42509"`
	// CPE for the template
	CPE string `json:"cpe,omitempty" yaml:"cpe,omitempty" jsonschema:"title=cpe for the template,description=CPE for the template,example=cpe:/a:vendor:product:version"`
}

// Info contains metadata information about a template
type Info struct {
	// Name should be good short summary that identifies what the template does
	Name string `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"title=name of the template,description=Name is a short summary of what the template does,type=string,required,example=Bower.json file disclosure"`
	// Author of the template. Multiple values can also be specified separated by commas
	Author string `json:"author,omitempty" yaml:"author,omitempty" jsonschema:"title=author of the template,description=Author is the author of the template,required,example=pdteam"`
	// Any tags for the template. Multiple values can also be specified separated by commas
	Tags string `json:"tags,omitempty" yaml:"tags,omitempty" jsonschema:"title=tags of the template,description=Any tags for the template,example=cve,cve2019,grafana,auth-bypass,dos"`
	// Description of the template. You can go in-depth here on what the template actually does
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,type=string,example=Bower is a package manager which stores package information in the bower.json file"`
	// Impact of the template. You can go in-depth here on impact of the template
	Impact string `json:"impact,omitempty" yaml:"impact,omitempty" jsonschema:"title=impact of the template,description=In-depth explanation on the impact of the issue found by the template,example=Successful exploitation of this vulnerability could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized access, data leakage, or data manipulation.,type=string"`
	// References for the template. This should contain links relevant to the template
	Reference []string `json:"reference,omitempty" yaml:"reference,omitempty" jsonschema:"title=references for the template,description=Links relevant to the template"`
	// Severity of the template
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty" jsonschema:"title=severity of the template,description=Severity of the template,enum=info,enum=low,enum=medium,enum=high,enum=critical"`
	// Metadata of the template
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template,type=object"`
	// Classification contains classification information about the template
	Classification *Classification `json:"classification,omitempty" yaml:"classification,omitempty" jsonschema:"title=classification info for the template,description=Classification information for the template,type=object"`
	// Remediation steps for the template. You can go in-depth here on how to mitigate the problem found by this template
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty" jsonschema:"title=remediation steps for the template,description=In-depth explanation on how to fix the issues found by the template,example=Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties,type=string"`
	// Zombie field for compatibility
	Zombie string `json:"zombie,omitempty" yaml:"zombie,omitempty" jsonschema:"title=zombie field,description=Zombie field for compatibility"`
}

type Template struct {
	// ID is the unique id for the template.
	// A good ID uniquely identifies what the requests in the template are doing.
	Id string `json:"id" yaml:"id" jsonschema:"title=id of the template,description=The Unique ID for the template,required,example=CVE-2021-19520,pattern=^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$"`

	// Fingers contains fingerprinting rules for the template (neutron internal field)
	Fingers []string `json:"finger,omitempty" yaml:"finger,omitempty" jsonschema:"title=fingerprinting rules,description=Fingerprinting rules for the template"`

	// Chains contains chaining rules for the template (neutron internal field)
	Chains []string `json:"chain,omitempty" yaml:"chain,omitempty" jsonschema:"title=chaining rules,description=Chaining rules for the template"`

	// Opsec specifies if the template should be executed in opsec mode (neutron internal field)
	Opsec bool `json:"opsec,omitempty" yaml:"opsec,omitempty" jsonschema:"title=opsec mode,description=Specifies if the template should be executed in opsec mode"`

	// Info contains metadata information about the template
	Info Info `json:"info" yaml:"info" jsonschema:"title=info for the template,description=Info contains metadata for the template,required,type=object"`

	// Variables contains any variables for the current template
	Variables protocols.Variable `yaml:"variables,omitempty" json:"variables,omitempty" jsonschema:"title=variables for the template,description=Variables contains any variables for the current template,type=object"`

	// HTTP contains the http request to make in the template
	RequestsHTTP []*http.Request `json:"http,omitempty" yaml:"http,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template"`

	// Requests contains the http request to make in the template (legacy compatibility)
	// WARNING: 'requests' will be deprecated and will be removed in a future release. Please use 'http' instead.
	Requests []*http.Request `json:"requests,omitempty" yaml:"requests,omitempty" jsonschema:"title=http requests to make,description=HTTP requests to make for the template,deprecated=true"`

	// Network contains the network request to make in the template
	RequestsNetwork []*network.Request `json:"network,omitempty" yaml:"network,omitempty" jsonschema:"title=network requests to make,description=Network requests to make for the template"`

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
