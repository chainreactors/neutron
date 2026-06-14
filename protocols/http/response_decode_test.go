package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResponseToDSLMapDecodesGzipBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(gzipBody(t, "vulnexists"))),
	}

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil, nil)
	require.Equal(t, "vulnexists", data["body"])
	require.Equal(t, len("vulnexists"), data["content_length"])
}

func TestResponseToDSLMapDecodesDeflateBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Content-Encoding": []string{"deflate"},
			"Content-Type":     []string{"text/plain"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(deflateBody(t, "vulnexists"))),
	}

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil, nil)
	require.Equal(t, "vulnexists", data["body"])
	require.Equal(t, len("vulnexists"), data["content_length"])
}

func TestResponseToDSLMapFallsBackWhenGzipHeaderIsInvalid(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"Content-Type":     []string{"text/plain"},
		},
		Body: ioutil.NopCloser(bytes.NewReader([]byte("plain-body"))),
	}

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil, nil)
	require.Equal(t, "plain-body", data["body"])
	require.Equal(t, len("plain-body"), data["content_length"])
}

func TestResponseToDSLMapDecodesGBKBodyAndTitle(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	body := []byte("<html><head><title>\xd3\xc3\xd3\xd1GRP-U8 \xb8\xdf\xd0\xa3\xc4\xda\xbf\xd8\xb9\xdc\xc0\xed\xc8\xed\xbc\xfe Manager \xb0\xe6</title></head><body>ok</body></html>")
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ContentLength: int64(len(body)),
		Header: http.Header{
			"Content-Type": []string{"text/html;charset=GBK"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(body)),
	}

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil, nil)
	require.Contains(t, data["body"], "用友GRP-U8 高校内控管理软件")
	require.Equal(t, "用友GRP-U8 高校内控管理软件 Manager 版", data["title"])
	require.Contains(t, data["response"], "用友GRP-U8 高校内控管理软件")
	require.Equal(t, int64(len(body)), data["content_length"])
}

func TestResponseToDSLMapDoesNotDecodeGBKMetaWithoutContentType(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)

	body := []byte("<html><head><meta charset=\"gbk\"><title>\xd3\xc3\xd3\xd1GRP-U8</title></head><body>ok</body></html>")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: ioutil.NopCloser(bytes.NewReader(body)),
	}

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil, nil)
	require.NotContains(t, data["body"], "用友GRP-U8")
	require.NotEqual(t, "用友GRP-U8", data["title"])
}

func gzipBody(t *testing.T, body string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func deflateBody(t *testing.T, body string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	_, err := writer.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buf.Bytes()
}
