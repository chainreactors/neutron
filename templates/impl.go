package templates

import (
	"errors"
	"fmt"
	"strings"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/protocols/executer"
	"github.com/chainreactors/neutron/protocols/network"
	"github.com/chainreactors/neutron/protocols/ssl"
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
	options = templateExecuterOptions(options, t.Variables)
	t.TotalRequests = 0

	// Merge tcp and udp fields into RequestsNetwork (aliases support)
	// FingerprintHub and other tools may use 'tcp' or 'udp' instead of 'network'
	if len(t.RequestsTCP) > 0 {
		t.RequestsNetwork = appendMissingNetworkRequests(t.RequestsNetwork, t.RequestsTCP)
	}
	if len(t.RequestsUDP) > 0 {
		t.RequestsNetwork = appendMissingNetworkRequests(t.RequestsNetwork, t.RequestsUDP)
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
	}
	if len(t.RequestsNetwork) > 0 {
		for i, req := range t.RequestsNetwork {
			if req == nil {
				return fmt.Errorf("network request at index %d is nil", i)
			}
			requests = append(requests, req)
		}
	}
	if len(t.RequestsTLS) > 0 {
		t.RequestsSSL = appendMissingSSLRequests(t.RequestsSSL, t.RequestsTLS)
	}
	if len(t.RequestsSSL) > 0 {
		for i, req := range t.RequestsSSL {
			if req == nil {
				return fmt.Errorf("ssl request at index %d is nil", i)
			}
			requests = append(requests, req)
		}
	}

	if len(requests) == 0 {
		return errors.New("cannot compiled any executor")
	}
	t.Executor = executer.NewExecuter(requests, options)
	if err := t.Executor.Compile(); err != nil {
		return err
	}
	t.TotalRequests = t.Executor.Requests()
	return nil
}

func appendMissingNetworkRequests(dst, src []*network.Request) []*network.Request {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[*network.Request]struct{}, len(dst))
	for _, req := range dst {
		seen[req] = struct{}{}
	}
	for _, req := range src {
		if _, ok := seen[req]; ok {
			continue
		}
		dst = append(dst, req)
		seen[req] = struct{}{}
	}
	return dst
}

func appendMissingSSLRequests(dst, src []*ssl.Request) []*ssl.Request {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[*ssl.Request]struct{}, len(dst))
	for _, req := range dst {
		seen[req] = struct{}{}
	}
	for _, req := range src {
		if _, ok := seen[req]; ok {
			continue
		}
		dst = append(dst, req)
		seen[req] = struct{}{}
	}
	return dst
}

// templateExecuterOptions creates the template-owned compile options. Compile
// binds variables to this copy only; variable evaluation stays in Execute.
func templateExecuterOptions(options *protocols.ExecuterOptions, variables protocols.Variable) *protocols.ExecuterOptions {
	if options == nil {
		options = &protocols.ExecuterOptions{
			Options: &protocols.Options{
				Timeout: 5,
			},
		}
	}
	templateOptions := *options
	if options.Options != nil {
		compiledOptions := *options.Options
		templateOptions.Options = &compiledOptions
	} else {
		templateOptions.Options = &protocols.Options{Timeout: 5}
	}
	templateOptions.Variables = variables
	return &templateOptions
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
//
// Deprecated: prefer ExecuteWithTransport. Passing a wholesale http.Client
// discards the template's compiled CheckRedirect/Jar/Timeout — templates with
// `redirects: false` then silently follow 302s and lose Location-header matches.
func (t *Template) ExecuteWithClient(input string, payload map[string]interface{}, client interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	ctx := protocols.NewScanContext(input, payload)
	ctx.Set("http.client", client)
	return t.Executor.Execute(ctx)
}

func (t *Template) ExecuteWithTransport(input string, payload map[string]interface{}, transport interface{}) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	ctx := protocols.NewScanContext(input, payload)
	ctx.Set("http.transport", transport)
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
