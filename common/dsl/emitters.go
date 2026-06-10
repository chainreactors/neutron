package dsl

import (
	"fmt"
	"strings"
)

// CertDataKeys lists every cert_* / raw_cert data-map key the converter may
// surface to emitters. Every Emitter partMap must map each of these
// explicitly: unmapped cert variables fall through to the header default and
// get rewritten as `header="cert_xxx: ..."` by isHeaderVariable.
//
// Kept in lockstep with common.XrayCertFields' values via a parity test in
// the convert/ package (which can import both without a cycle).
var CertDataKeys = []string{
	"cert_subject",
	"cert_issuer",
	"cert_common_name",
	"cert_organization",
	"cert_not_before",
	"cert_not_after",
	"cert_dnsnames",
	"cert_serial",
	"raw_cert",
}

// --- FOFA ---

type FOFAEmitter struct{}

var fofaPartMap = map[string]string{
	"body":              "body",
	"all_headers":       "header",
	"header":            "header",
	"title":             "title",
	"status_code":       "status_code",
	"content_type":      "header",
	"server":            "server",
	"banner":            "banner",
	"cert":              "cert",
	"cert_subject":      "cert.subject",
	"cert_issuer":       "cert.issuer",
	"cert_common_name":  "certs_subject_cn",
	"cert_organization": "certs_subject_org",
	// fofa has no per-field DNS-SAN / serial / validity cert syntax; fall back
	// to the whole-certificate substring match. raw_cert.bcontains is
	// equivalent to fofa cert= so it also maps to the whole-cert field.
	"cert_dnsnames":   "cert",
	"cert_serial":     "cert",
	"cert_not_before": "cert",
	"cert_not_after":  "cert",
	"raw_cert":        "cert",
	"protocol":        "protocol",
}

func (f *FOFAEmitter) Field(part string) string {
	if v, ok := fofaPartMap[part]; ok {
		return v
	}
	// Unmapped variables (location, set_cookie, x_powered_by, etc.)
	// are individual header fields from xray conversion. Every cert_* key
	// must be explicitly mapped above — see CertDataKeys / parity test.
	return "header"
}

func (f *FOFAEmitter) Contains(field, value string) string {
	return fmt.Sprintf(`%s="%s"`, field, fofaEscape(value))
}
func (f *FOFAEmitter) Equals(field, value string) string {
	return fmt.Sprintf(`%s=="%s"`, field, fofaEscape(value))
}
func (f *FOFAEmitter) NotEquals(field, value string) string {
	return fmt.Sprintf(`%s!="%s"`, field, fofaEscape(value))
}

func fofaEscape(s string) string {
	return strings.Replace(s, `"`, `\"`, -1)
}
func (f *FOFAEmitter) StatusCode(code int) string {
	return fmt.Sprintf(`status_code="%d"`, code)
}
func (f *FOFAEmitter) FaviconHash(hash string) (string, error) {
	return fmt.Sprintf(`icon_hash="%s"`, hash), nil
}
func (f *FOFAEmitter) And(clauses ...string) string { return strings.Join(clauses, " && ") }
func (f *FOFAEmitter) Or(clauses ...string) string  { return strings.Join(clauses, " || ") }
func (f *FOFAEmitter) Not(clause string) string     { return fmt.Sprintf(`!(%s)`, clause) }
func (f *FOFAEmitter) Group(clause string) string   { return "(" + clause + ")" }

// --- Hunter ---

type HunterEmitter struct{}

var hunterPartMap = map[string]string{
	"body":         "body",
	"all_headers":  "header",
	"header":       "header",
	"title":        "title",
	"status_code":  "status_code",
	"content_type": "header",
	"server":       "server",
	"banner":       "banner",
	"cert":         "cert",
	"cert_subject": "cert.subject",
	"cert_issuer":  "cert.issuer",
	// hunter has no fine-grained cert subfields; fall back to whole-cert match.
	"cert_common_name":  "cert",
	"cert_organization": "cert",
	"cert_dnsnames":     "cert",
	"cert_serial":       "cert",
	"cert_not_before":   "cert",
	"cert_not_after":    "cert",
	"raw_cert":          "cert",
	"protocol":          "protocol",
}

func (h *HunterEmitter) Field(part string) string {
	if v, ok := hunterPartMap[part]; ok {
		return v
	}
	// Cert keys are all explicitly mapped above (see CertDataKeys); anything
	// else is an individual response header.
	return "header"
}

func (h *HunterEmitter) Contains(field, value string) string {
	return fmt.Sprintf(`%s="%s"`, field, fofaEscape(value))
}
func (h *HunterEmitter) Equals(field, value string) string {
	return fmt.Sprintf(`%s=="%s"`, field, fofaEscape(value))
}
func (h *HunterEmitter) NotEquals(field, value string) string {
	return fmt.Sprintf(`%s!="%s"`, field, fofaEscape(value))
}

func (h *HunterEmitter) StatusCode(code int) string {
	return fmt.Sprintf(`status_code="%d"`, code)
}
func (h *HunterEmitter) FaviconHash(hash string) (string, error) {
	return fmt.Sprintf(`icon_hash="%s"`, hash), nil
}
func (h *HunterEmitter) And(clauses ...string) string { return strings.Join(clauses, " && ") }
func (h *HunterEmitter) Or(clauses ...string) string  { return strings.Join(clauses, " || ") }
func (h *HunterEmitter) Not(clause string) string     { return fmt.Sprintf(`!(%s)`, clause) }
func (h *HunterEmitter) Group(clause string) string   { return "(" + clause + ")" }

// --- Censys ---

type CensysEmitter struct{}

var censysPartMap = map[string]string{
	"body":              "services.http.response.body",
	"all_headers":       "services.http.response.headers",
	"header":            "services.http.response.headers",
	"title":             "services.http.response.html_title",
	"status_code":       "services.http.response.status_code",
	"content_type":      "services.http.response.headers.content_type",
	"server":            "services.http.response.headers.server",
	"banner":            "services.banner",
	"cert":              "services.certificate",
	"cert_subject":      "services.tls.certificates.leaf_data.subject.common_name",
	"cert_issuer":       "services.tls.certificates.leaf_data.issuer.common_name",
	"cert_common_name":  "services.tls.certificates.leaf_data.subject.common_name",
	"cert_organization": "services.tls.certificates.leaf_data.subject.organization",
	"cert_dnsnames":     "services.tls.certificates.leaf_data.names",
	// serial / not_before / not_after are not exposed as per-field queries on
	// censys host records (only the certificates index); fall back to the
	// whole-certificate field so the value still matches as a substring.
	"cert_serial":     "services.certificate",
	"cert_not_before": "services.certificate",
	"cert_not_after":  "services.certificate",
	"raw_cert":        "services.certificate",
	"protocol":        "services.service_name",
}

func (c *CensysEmitter) Field(part string) string {
	if v, ok := censysPartMap[part]; ok {
		return v
	}
	// Cert keys are all explicitly mapped above (see CertDataKeys); anything
	// else is an individual response header.
	return "services.http.response.headers"
}

func (c *CensysEmitter) Contains(field, value string) string {
	return fmt.Sprintf(`%s: "%s"`, field, value)
}
func (c *CensysEmitter) Equals(field, value string) string {
	return fmt.Sprintf(`%s="%s"`, field, value)
}
func (c *CensysEmitter) NotEquals(field, value string) string {
	return fmt.Sprintf(`NOT %s: "%s"`, field, value)
}
func (c *CensysEmitter) StatusCode(code int) string {
	return fmt.Sprintf(`services.http.response.status_code: %d`, code)
}
func (c *CensysEmitter) FaviconHash(hash string) (string, error) {
	return "", fmt.Errorf("censys does not support favicon hash queries")
}
func (c *CensysEmitter) And(clauses ...string) string { return strings.Join(clauses, " AND ") }
func (c *CensysEmitter) Or(clauses ...string) string  { return strings.Join(clauses, " OR ") }
func (c *CensysEmitter) Not(clause string) string     { return "NOT " + clause }
func (c *CensysEmitter) Group(clause string) string   { return "(" + clause + ")" }

// --- Registry ---

var emitters = map[string]func() Emitter{
	"fofa":   func() Emitter { return &FOFAEmitter{} },
	"hunter": func() Emitter { return &HunterEmitter{} },
	"censys": func() Emitter { return &CensysEmitter{} },
}

func GetEmitter(platform string) (Emitter, bool) {
	fn, ok := emitters[platform]
	if !ok {
		return nil, false
	}
	return fn(), true
}

func RegisterEmitter(platform string, factory func() Emitter) {
	emitters[platform] = factory
}
