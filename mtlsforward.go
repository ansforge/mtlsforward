// Package mtlsforward implements a middleware for
// Traefik Proxy that forwards mTLS certificates inside
// HTTP headers.
package mtlsforward

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Config handles configuration of the sslClientCert (e.g. SSL_CLIENT_CERT) and sslCertChainPrefix (e.g. SSL_CERT_CHAIN) headers.
type Config struct {
	Headers       map[string]string
	EncodePem     bool
	EncodeURL     bool
	RemoveNewline bool
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers:       make(map[string]string),
		EncodePem:     false,
		EncodeURL:     false,
		RemoveNewline: true,
	}
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	_, ok := config.Headers["sslClientCert"]
	if !ok {
		return nil, fmt.Errorf("configuration option 'sslClientCert' not set")
	}
	_, ok = config.Headers["sslCertChainPrefix"]
	if !ok {
		return nil, fmt.Errorf("configuration option 'sslCertChainPrefix' not set")
	}

	return &mTLSForward{
		headers:       config.Headers,
		encodePem:     config.EncodePem,
		encodeURL:     config.EncodeURL,
		removeNewline: config.RemoveNewline,
		next:          next,
		name:          name,
	}, nil
}

type mTLSForward struct {
	headers       map[string]string
	encodePem     bool
	encodeURL     bool
	removeNewline bool
	next          http.Handler
	name          string
}

func (m mTLSForward) encodeCertificate(certBytes *[]byte) string {
	encodedCert := ""

	if m.encodePem {
		encodedCert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: *certBytes}))
	} else {
		encodedCert = base64.StdEncoding.EncodeToString(*certBytes)
                encodedCert = "-----BEGIN CERTIFICATE-----" + encodedCert + "-----END CERTIFICATE-----"
		//encodedCert = base64.StdEncoding.EncodeToString([]byte(encodedCert))
	}

	if m.encodeURL {
		encodedCert = url.QueryEscape(encodedCert)
	}

	if !m.encodeURL && m.removeNewline {
		encodedCert = strings.ReplaceAll(encodedCert, "\n", " ")
	}
	return encodedCert
}

func (m mTLSForward) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// are we using mTLS?
	if request.TLS != nil && len(request.TLS.PeerCertificates) > 0 {
		for i, cert := range request.TLS.PeerCertificates {
			fmt.Println("Found certificate with subject", cert.Subject, "issued by", cert.Issuer)
			certString := m.encodeCertificate(&cert.Raw)
			if i == 0 {
				request.Header.Set(m.headers["sslClientCert"], certString)
			} else {
				// part of chain
				headerName := m.headers["sslCertChainPrefix"] + "_" + strconv.Itoa(i-1)
				request.Header.Set(headerName, certString)
			}
		}
	}
	fmt.Println("Ready for next plugin")

	// call to next plugin
	m.next.ServeHTTP(writer, request)
}
