package protocols

import (
	"context"
	"net"
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
	// ProxyURL 为 HTTP 代理地址（如 http://127.0.0.1:8080），
	// HTTP 协议包内部根据此字段构建 transport.Proxy。
	ProxyURL string
}
