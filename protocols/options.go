package protocols

import (
	"context"
	"net"
	"net/http"
	"net/url"
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
