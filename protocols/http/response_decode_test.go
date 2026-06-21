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

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil)
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

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil)
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

	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil)
	require.Equal(t, "plain-body", data["body"])
	require.Equal(t, len("plain-body"), data["content_length"])
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
