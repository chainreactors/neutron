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
	"golang.org/x/text/encoding/simplifiedchinese"
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

// TestResponseToDSLMapDecodesGbkBody mirrors projectdiscovery/nuclei#1018 (fixed
// in v2.5.3): a GBK-family body declared via Content-Type is recoded to UTF-8 so
// UTF-8 matchers match. nuclei v3 dropped this charset step; neutron restores it.
func TestResponseToDSLMapDecodesGbkBody(t *testing.T) {
	utf8Text := "电子文档安全管理系统" // the exact phrase from nuclei#1018
	gbkBytes, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(utf8Text))
	require.NoError(t, err)

	for _, ct := range []string{
		"text/html; charset=gbk",
		"text/html; charset=GB2312", // charset match is case-insensitive
		"text/html; charset=gb18030",
	} {
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header:     http.Header{"Content-Type": []string{ct}},
			Body:       ioutil.NopCloser(bytes.NewReader(gbkBytes)),
		}
		data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil)
		require.Equalf(t, utf8Text, data["body"], "charset=%s did not decode to UTF-8", ct)
	}
}

// A body whose Content-Type does NOT declare a GBK charset is left untouched.
func TestResponseToDSLMapLeavesNonGbkBodyUntouched(t *testing.T) {
	utf8Text := "电子文档安全管理系统"
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       ioutil.NopCloser(bytes.NewReader([]byte(utf8Text))),
	}
	data := (&Request{}).responseToDSLMap(req, resp, "https://example.com", "https://example.com", time.Second, nil, nil)
	require.Equal(t, utf8Text, data["body"])
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
