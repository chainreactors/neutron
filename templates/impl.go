package templates

import (
	"errors"
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
	options = templateExecuterOptions(options, t.Variables)

	if err := t.Parse(); err != nil {
		return err
	}
	if len(t.parsedRequests) == 0 {
		return errors.New("cannot compiled any executor")
	}

	t.Executor = executer.NewExecuter(t.parsedRequests, options)
	if err := t.Executor.Compile(); err != nil {
		return err
	}
	t.TotalRequests = t.Executor.Requests()
	return nil
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
func (t *Template) ExecuteWithClient(input string, payload map[string]interface{}, client *http.Client) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	ctx := protocols.NewScanContext(input, payload)
	ctx.Client = client
	return t.Executor.Execute(ctx)
}

// ExecuteWithTransport runs the template using the provided RoundTripper for
// this execution only. Unlike ExecuteWithClient, the template's compiled
// CheckRedirect, cookie jar, and timeout are preserved — only the transport
// layer is swapped. Active-match engines that need to plug in a caching or
// instrumented transport should prefer this.
func (t *Template) ExecuteWithTransport(input string, payload map[string]interface{}, transport http.RoundTripper) (*operators.Result, error) {
	if t.Executor.Options().Options.Opsec && t.Opsec {
		common.Debug("(opsec!!!) skip template %s", t.Id)
		return nil, protocols.OpsecError
	}
	ctx := protocols.NewScanContext(input, payload)
	ctx.Transport = transport
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
