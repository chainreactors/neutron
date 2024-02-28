package templates

import (
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"strings"
)

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
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}

	if len(t.RequestsNetwork) > 0 {
		for _, req := range t.RequestsNetwork {
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}

	//if len(t.RequestFile) > 0 {
	//	for _, req := range t.RequestFile {
	//		requests = append(requests, &req)
	//	}
	//	t.Executor = executer.NewExecuter(requests, options)
	//}

	if t.Executor != nil {
		err = t.Executor.Compile()
		if err != nil {
			return err
		}
		t.TotalRequests += t.Executor.Requests()
	}
	return nil
}

func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.NeutronLog.Debugf("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	return t.Executor.Execute(protocols.NewScanContext(input, payload))
}
