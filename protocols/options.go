package protocols

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/chainreactors/neutron/common/dsl"
)

type Options struct {
	VarsPayload map[string]interface{}
	AttackType  string
	Opsec       bool
	Timeout     int
	TextOnly    bool
	// DialContext 非 nil 时用于建立出站连接（http 与 network 协议），
	// 使每个 ExecuterOptions 携带各自的拨号器（可为代理），从而并发安全、
	// 无需改写任何全局 transport。由上层（如 SDK 经 proxyclient）注入。
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// Proxy 为 HTTP-CONNECT 风格代理（transport.Proxy），供 http 协议使用。
	// 与 DialContext 二选一；二者皆 per-execution，不改写全局。
	Proxy func(*http.Request) (*url.URL, error)
}

var staticPreprocessorRE = regexp.MustCompile(`\{\{\s*(randstr(?:_[A-Za-z0-9_]+)?|randnum(?:_[A-Za-z0-9_]+)?)\s*\}\}`)

// StaticVariablesFor returns template-level static values used to emulate
// nuclei preprocessors such as {{randstr}}. Values are generated once and then
// shared by every request block for this compiled template.
func (options *ExecuterOptions) StaticVariablesFor(parts ...string) map[string]interface{} {
	if options == nil {
		return nil
	}
	options.staticVariablesMu.Lock()
	defer options.staticVariablesMu.Unlock()

	if options.StaticVariables == nil {
		options.StaticVariables = make(map[string]interface{})
	}
	ensureStaticVariable(options.StaticVariables, "randstr")
	ensureStaticVariable(options.StaticVariables, "randnum")

	for _, part := range parts {
		if part == "" {
			continue
		}
		for _, match := range staticPreprocessorRE.FindAllStringSubmatch(part, -1) {
			if len(match) > 1 {
				ensureStaticVariable(options.StaticVariables, match[1])
			}
		}
	}

	result := make(map[string]interface{}, len(options.StaticVariables))
	for key, value := range options.StaticVariables {
		result[key] = value
	}
	return result
}

func ensureStaticVariable(values map[string]interface{}, name string) {
	if _, ok := values[name]; ok {
		return
	}
	if strings.HasPrefix(name, "randnum") {
		values[name] = dsl.RandNum(4)
		return
	}
	values[name] = dsl.RandStr(8)
}
