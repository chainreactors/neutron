package templates

import (
	"github.com/chainreactors/found/pkg/proton/operators"
	protocols "github.com/chainreactors/found/pkg/proton/protocols"
	"github.com/chainreactors/found/pkg/proton/protocols/executer"
	"github.com/chainreactors/found/pkg/proton/protocols/file"
	"github.com/chainreactors/found/pkg/proton/protocols/http"
	"github.com/chainreactors/found/pkg/proton/protocols/network"
	"strings"
)

type Template struct {
	Id      string   `json:"id" yaml:"id"`
	Fingers []string `json:"finger" yaml:"finger"`
	Chains  []string `json:"chain" yaml:"chain"`
	Info    struct {
		Name string `json:"name" yaml:"name"`
		//Author    string `json:"author"`
		Severity    string `json:"severity" yaml:"severity"`
		Description string `json:"description" yaml:"description"`
		//Reference string `json:"reference"`
		//Vendor    string `json:"vendor"`
		Tags string `json:"tags" yaml:"tags"`
	} `json:"info" yaml:"info"`
	RequestFile     []file.Request    `json:"request_file" yaml:"file"`
	RequestsHTTP    []http.Request    `json:"requests" yaml:"requests"`
	RequestsNetwork []network.Request `json:"network" yaml:"network"`
	//RequestsTCP []tcp.Request `json:"network"`
	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executor is the actual template executor for running template requests
	Executor *executer.Executer `yaml:"-" json:"-"`
}

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}
}

func (t *Template) Compile(options *protocols.ExecuterOptions) error {
	var requests []protocols.Request
	var err error
	if len(t.RequestsHTTP) > 0 {
		for _, req := range t.RequestsHTTP {
			requests = append(requests, &req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}
	if len(t.RequestsNetwork) > 0 {
		for _, req := range t.RequestsNetwork {
			requests = append(requests, &req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}

	if len(t.RequestFile) > 0 {
		for _, req := range t.RequestFile {
			requests = append(requests, &req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}
	
	if t.Executor != nil {
		err = t.Executor.Compile()
		if err != nil {
			return err
		}
		t.TotalRequests += t.Executor.Requests()
	}
	return nil
}

func (t *Template) Execute(input string) (*operators.Result, bool) {
	res, err := t.Executor.Execute(input)
	if err != nil || res == nil {
		return nil, false
	}
	return res, true
}
