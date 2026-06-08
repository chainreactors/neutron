package templates

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
)

func (t *Template) GetTags() []string {
	if t.Info.Tags != "" {
		return strings.Split(t.Info.Tags, ",")
	}
	return []string{}

}

func (t *Template) Compile(options *protocols.ExecuterOptions) error {
	if t == nil {
		return errors.New("template is nil")
	}
	var requests []protocols.Request
	var err error
	if options == nil {
		options = &protocols.ExecuterOptions{
			Options: &protocols.Options{
				Timeout: 5,
			},
		}
	}

	if t.Variables.Len() > 0 {
		options.Variables = t.Variables
	}

	// Merge tcp and udp fields into RequestsNetwork (aliases support)
	// FingerprintHub and other tools may use 'tcp' or 'udp' instead of 'network'
	if len(t.RequestsTCP) > 0 {
		t.RequestsNetwork = append(t.RequestsNetwork, t.RequestsTCP...)
	}
	if len(t.RequestsUDP) > 0 {
		t.RequestsNetwork = append(t.RequestsNetwork, t.RequestsUDP...)
	}

	if requestHTTP := t.GetRequests(); len(requestHTTP) > 0 {
		for i, req := range requestHTTP {
			if req == nil {
				return fmt.Errorf("http request at index %d is nil", i)
			}
			if req.Unsafe {
				return fmt.Errorf("not impl unsafe request %s", req.Name)
			}
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}
	if len(t.RequestsNetwork) > 0 {
		for i, req := range t.RequestsNetwork {
			if req == nil {
				return fmt.Errorf("network request at index %d is nil", i)
			}
			requests = append(requests, req)
		}
		t.Executor = executer.NewExecuter(requests, options)
	}

	if t.Executor != nil {
		err = t.Executor.Compile()
		if err != nil {
			return err
		}
		t.TotalRequests += t.Executor.Requests()
	} else {
		return errors.New("cannot compiled any executor")
	}
	return nil
}

func (t *Template) Execute(input string, payload map[string]interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	return t.Executor.Execute(protocols.NewScanContext(input, payload))
}

// ExecuteWithClient runs the template using the provided HTTP client for this
// execution only. The client is threaded through the ScanContext down to request
// execution, so the shared compiled template is never mutated at runtime — making
// concurrent active-match calls safe. A nil client falls back to Execute's behavior.
func (t *Template) ExecuteWithClient(input string, payload map[string]interface{}, client *http.Client) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	ctx := protocols.NewScanContext(input, payload)
	ctx.Client = client
	return t.Executor.Execute(ctx)
}

// ExecuteWithEvents executes the template and returns both the final result
// and all per-step ResultEvents (each carrying its own Request/Response).
func (t *Template) ExecuteWithEvents(input string, payload map[string]interface{}) (*operators.Result, []*protocols.ResultEvent, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, nil, protocols.OpsecError
	}
	ctx := protocols.NewScanContext(input, payload)
	result, err := t.Executor.Execute(ctx)
	if err != nil {
		return nil, nil, err
	}
	return result, ctx.GenerateResult(), nil
}
