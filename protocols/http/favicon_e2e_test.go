package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/utils/encode"
	"github.com/stretchr/testify/require"
)

// 模拟 favicon 二进制内容
var testFaviconBody = []byte("FAKE-ICON-BINARY-DATA")

func TestFaviconMatcherSupportsMmh3AndMd5(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(testFaviconBody)
	}))
	defer server.Close()

	mmh3Hash := encode.Mmh3Hash32(testFaviconBody)
	md5Hash := encode.Md5Hash(testFaviconBody)
	t.Logf("mmh3=%s md5=%s", mmh3Hash, md5Hash)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/favicon.ico", nil)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)

	request := &Request{
		options: &protocols.ExecuterOptions{Options: &protocols.Options{Timeout: 5}},
	}
	event := request.responseToDSLMap(req, resp, server.URL, server.URL+"/favicon.ico", 100*time.Millisecond, nil, nil)

	// 验证 favicon_hash 包含 mmh3 和 md5
	faviconHash := fmt.Sprint(event["favicon_hash"])
	require.Contains(t, faviconHash, mmh3Hash)
	require.Contains(t, faviconHash, md5Hash)

	// 场景 1: converter 生成的模板 (mmh3 hash)
	mmh3Matcher := &operators.Matcher{Type: "favicon", Part: "favicon_hash", Hash: []string{mmh3Hash}}
	require.NoError(t, mmh3Matcher.CompileMatchers())
	matched, _ := request.Match(event, mmh3Matcher)
	require.True(t, matched, "mmh3 matcher should match (xray converter scenario)")

	// 场景 2: fingerprinthub 模板 (md5 hash)
	md5Matcher := &operators.Matcher{Type: "favicon", Part: "favicon_hash", Hash: []string{md5Hash}}
	require.NoError(t, md5Matcher.CompileMatchers())
	matched, _ = request.Match(event, md5Matcher)
	require.True(t, matched, "md5 matcher should match (fingerprinthub scenario)")

	// 场景 3: 不匹配的 hash
	wrongMatcher := &operators.Matcher{Type: "favicon", Part: "favicon_hash", Hash: []string{"wronghash"}}
	require.NoError(t, wrongMatcher.CompileMatchers())
	matched, _ = request.Match(event, wrongMatcher)
	require.False(t, matched, "wrong hash should not match")
}
