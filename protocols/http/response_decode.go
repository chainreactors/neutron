package http

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// readResponseBody decodes HTTP content encodings (gzip/deflate) and, mirroring
// nuclei v2 (projectdiscovery/nuclei#1018, fixed in v2.5.3), converts GBK-family
// bodies (gbk/gb2312/gb18030 declared via Content-Type) into UTF-8 so UTF-8
// matchers match. nuclei v3 dropped this charset step; we restore it here so
// every consumer (finger / POC / any future entry) is covered uniformly.
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
		decodedBody = rawBody
	}

	// nuclei v2 compat: decode GBK-family bodies declared via Content-Type to UTF-8.
	if isContentTypeGbk(resp.Header.Get("Content-Type")) {
		if gbkDecoded, gErr := decodegbk(decodedBody); gErr == nil {
			return gbkDecoded, nil
		}
	}

	return decodedBody, nil
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

// decodegbk converts a GBK byte slice to UTF-8. Mirrors nuclei v2.5.3
// (pkg/protocols/http/utils.go) via golang.org/x/text/encoding/simplifiedchinese.
func decodegbk(s []byte) ([]byte, error) {
	r := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// isContentTypeGbk reports whether the Content-Type header declares a GBK-family
// charset (gbk/gb2312/gb18030). Matches nuclei v2.5.3: only server-declared
// charsets trigger recoding (no auto-detection), exactly as v2 did.
func isContentTypeGbk(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.Contains(contentType, "gbk") ||
		strings.Contains(contentType, "gb2312") ||
		strings.Contains(contentType, "gb18030")
}
