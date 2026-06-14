package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func readResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}

	rawBody, err := ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	decodedBody, err := decodeResponseBody(rawBody, resp.Header.Get("Content-Encoding"))
	if err != nil {
		// Fall back to the raw body so malformed encoding headers do not abort matching.
		return rawBody, nil
	}

	return decodeResponseTextBytes(decodedBody, resp.Header.Get("Content-Type"))
}

func decodeResponseBody(body []byte, contentEncoding string) ([]byte, error) {
	encodings, ok := supportedEncodings(contentEncoding)
	if !ok || len(encodings) == 0 {
		return body, nil
	}

	decoded := body
	var err error
	for i := len(encodings) - 1; i >= 0; i-- {
		decoded, err = decodeBodyWithEncoding(decoded, encodings[i])
		if err != nil {
			return nil, err
		}
	}

	return decoded, nil
}

func supportedEncodings(contentEncoding string) ([]string, bool) {
	if strings.TrimSpace(contentEncoding) == "" {
		return nil, true
	}

	parts := strings.Split(contentEncoding, ",")
	encodings := make([]string, 0, len(parts))
	for _, part := range parts {
		encoding := strings.ToLower(strings.TrimSpace(part))
		switch encoding {
		case "", "identity":
			continue
		case "gzip", "x-gzip", "deflate":
			encodings = append(encodings, encoding)
		default:
			return nil, false
		}
	}

	return encodings, true
}

func decodeBodyWithEncoding(body []byte, encoding string) ([]byte, error) {
	var (
		reader io.ReadCloser
		err    error
	)

	switch encoding {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(body))
	default:
		return body, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return ioutil.ReadAll(reader)
}

func decodeResponseTextBytes(body []byte, contentType string) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var reader io.Reader
	contentType = strings.ToLower(contentType)
	switch {
	case strings.Contains(contentType, "gbk"), strings.Contains(contentType, "gb2312"), strings.Contains(contentType, "gb18030"):
		reader = transform.NewReader(bytes.NewReader(body), simplifiedchinese.GBK.NewDecoder())
	case strings.Contains(contentType, "windows-1251"), strings.Contains(contentType, "cp1251"), strings.Contains(contentType, "cp-1251"):
		reader = transform.NewReader(bytes.NewReader(body), charmap.Windows1251.NewDecoder())
	default:
		return body, nil
	}

	decoded, err := ioutil.ReadAll(reader)
	if err != nil {
		return body, nil
	}
	return decoded, nil
}
