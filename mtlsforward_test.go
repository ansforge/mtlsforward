package mtlsforward_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ansforge/mtlsforward"
)

func TestDemo(t *testing.T) {
	const caPEM = `-----BEGIN CERTIFICATE-----
MIIC+jCCAeKgAwIBAgIIWNc0nQJTjRcwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
AwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQxMDBaGA85OTk5MTIzMTIzNTk1OVowEjEQ
MA4GA1UEAwwHdGVzdF9jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMhY4qJQlsihrq7GzZKlXjEadqHUKrP7po6fSaWlI0OQ5vPo+NP//EDB1aSnra8z
f8sXuN6rujQU7aFMe0jV2gat5qFNWxdEDuA42npKXlJZaes3JdBcoLaAftdSxL9d
keTIbqumTR3esN/z6q/AYcgm7qbIBSTzVZSwKnDihhk3rgWgi9R0h1wjM+1sgBMo
4rp4co0pCbW0yJ0gt6bZY99Bf/X1mymbDThzXMXvxI2mMF52MqqlQk3XowCCingl
C9bdfpu+18qTHmaDpXCKPcoyy+M5waoRTepuTJbxiMURuytgoT6Auu04LJPZ204p
XzUMFAoIyDI7iv1+K6AQQBcCAwEAAaNSMFAwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUam+/bLYpLcOV2ozA42noBkTZyRIwCwYDVR0PBAQDAgEGMBEGCWCGSAGG
+EIBAQQEAwIABzANBgkqhkiG9w0BAQsFAAOCAQEAGi0XFj3W3fC/cq2BaiTgpzB4
OiYbGjjourf8foTTef0sDOiWol7qwoYhVHLHQgchSdrzj5uBQDewo192ByMa0OZZ
rtECaaEZo7zW3ny/Oo16pCPgzaY4xpzdU7Ln4fyTftzDHxl81Nqt2GlZDn967/fJ
PQAiyZJRbFKSjQ0QvyUootkXVhoewHpx8QDDLvWL5GOFTb2o5ZNJCiJYWRwbRD4S
c8AZBkU8y+XQ7EIzVyJhzNfXzwzjFDE8Yw7zMkFjTL/8XuOq6lPPZrpBEOZ/bHHu
Kh67UBwBlTD9H/hoTcRESuuQlJ3RGUWUEfIiIV5WxrpfdeJpHY/wnaGTTqSruA==
-----END CERTIFICATE-----
`

	const certPEM = `-----BEGIN CERTIFICATE-----
MIIDEDCCAfigAwIBAgIIQXxeH1vM+tYwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
AwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQ1MDBaGA85OTk5MTIzMTIzNTk1OVowFjEU
MBIGA1UEAwwLbXRsc19jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDA4g7AcPxzOraD65UYakPOZ8c43E7yBZqcF85ZvfUrN5/eOItQUT2Kqw/M
x6ynfvliPHbqBaoCmuaJzigS5CJc4x3/nuYKKycqJaGXiQJ1i3hEQk+04TGdkTs0
4kzKkS1PNYOZCX11P/3hdQ4DykfxcfqKqvGLCCVGPbyr7C+hPzzIkppPJuMOM9oJ
Sb1AW3a+T2uOtI4J1wLq7IqlSyCzMVSzCI9CJ8vGIUe4RGlFR90ONHHYxz5EtkQq
lVM27o2zGqT4dPX5XMmAFdjeKIgS6SOAwSJjmLPvdKmvFkweeKqPPNwghjICokzb
0TVRorVYWSIGFXiNBQl1QLX2/A2FAgMBAAGjZDBiMAwGA1UdEwEB/wQCMAAwHQYD
VR0OBBYEFC0Po/+Vc34sMuYCOxVL7FOk4yg+MAsGA1UdDwQEAwIDuDATBgNVHSUE
DDAKBggrBgEFBQcDAjARBglghkgBhvhCAQEEBAMCBaAwDQYJKoZIhvcNAQELBQAD
ggEBADQHzmjRUsFaT8fiwt0QAh3uX18JVWiKGbC5YC6heBeqfq32TUmIqLDZl9lk
hnuI1+w0LTmn415bVz2xJsFmRXBMludH8MhQbkrL1hKSjrlEtF7K5pa3gt8lanEq
X2JPLSv2verLZr3ptJ6TI2RfbmdhRU5fEPETfPaf+2EkyZ8l6UbbUm7PV6XQsINX
GyxAcQq/xlonGAhWuAQ23nDP7TF8QmVAiY/C8TgidEvYmmWsna0ezOeDM/w7KX6+
zegYc03Fmul9vlGu9ZP70SNmyVFL//LIzXf16rvsMLNeWho5d8Y0usywXjuuS2WE
DqH21BZ19OniZNd5kW5xUaF7J0A=
-----END CERTIFICATE-----
`

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	clientBlock, _ := pem.Decode([]byte(certPEM))
	if clientBlock == nil {
		t.Fatal("failed to parse client certificate PEM")
	}
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatal("failed to parse client certificate: " + err.Error())
	}

	caBlock, _ := pem.Decode([]byte(caPEM))
	if caBlock == nil {
		t.Fatal("failed to parse ca certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal("failed to parse ca certificate: " + err.Error())
	}

	certChain := []*x509.Certificate{clientCert, caCert}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.TLS = &tls.ConnectionState{
		PeerCertificates: certChain,
	}

	// Test with base64 encoding, no url encoding

	cfg := mtlsforward.CreateConfig()
	cfg.Headers["sslClientCert"] = "SSL_CLIENT_CERT"
	cfg.Headers["sslCertChainPrefix"] = "CERT_CHAIN"
	handler, err := mtlsforward.New(ctx, next, cfg, "mtlsforward-plugin")
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "SSL_CLIENT_CERT", "MIIDEDCCAfigAwIBAgIIQXxeH1vM+tYwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQ1MDBaGA85OTk5MTIzMTIzNTk1OVowFjEUMBIGA1UEAwwLbXRsc19jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA4g7AcPxzOraD65UYakPOZ8c43E7yBZqcF85ZvfUrN5/eOItQUT2Kqw/Mx6ynfvliPHbqBaoCmuaJzigS5CJc4x3/nuYKKycqJaGXiQJ1i3hEQk+04TGdkTs04kzKkS1PNYOZCX11P/3hdQ4DykfxcfqKqvGLCCVGPbyr7C+hPzzIkppPJuMOM9oJSb1AW3a+T2uOtI4J1wLq7IqlSyCzMVSzCI9CJ8vGIUe4RGlFR90ONHHYxz5EtkQqlVM27o2zGqT4dPX5XMmAFdjeKIgS6SOAwSJjmLPvdKmvFkweeKqPPNwghjICokzb0TVRorVYWSIGFXiNBQl1QLX2/A2FAgMBAAGjZDBiMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFC0Po/+Vc34sMuYCOxVL7FOk4yg+MAsGA1UdDwQEAwIDuDATBgNVHSUEDDAKBggrBgEFBQcDAjARBglghkgBhvhCAQEEBAMCBaAwDQYJKoZIhvcNAQELBQADggEBADQHzmjRUsFaT8fiwt0QAh3uX18JVWiKGbC5YC6heBeqfq32TUmIqLDZl9lkhnuI1+w0LTmn415bVz2xJsFmRXBMludH8MhQbkrL1hKSjrlEtF7K5pa3gt8lanEqX2JPLSv2verLZr3ptJ6TI2RfbmdhRU5fEPETfPaf+2EkyZ8l6UbbUm7PV6XQsINXGyxAcQq/xlonGAhWuAQ23nDP7TF8QmVAiY/C8TgidEvYmmWsna0ezOeDM/w7KX6+zegYc03Fmul9vlGu9ZP70SNmyVFL//LIzXf16rvsMLNeWho5d8Y0usywXjuuS2WEDqH21BZ19OniZNd5kW5xUaF7J0A=")
	assertHeader(t, req, "CERT_CHAIN_0", "MIIC+jCCAeKgAwIBAgIIWNc0nQJTjRcwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQxMDBaGA85OTk5MTIzMTIzNTk1OVowEjEQMA4GA1UEAwwHdGVzdF9jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMhY4qJQlsihrq7GzZKlXjEadqHUKrP7po6fSaWlI0OQ5vPo+NP//EDB1aSnra8zf8sXuN6rujQU7aFMe0jV2gat5qFNWxdEDuA42npKXlJZaes3JdBcoLaAftdSxL9dkeTIbqumTR3esN/z6q/AYcgm7qbIBSTzVZSwKnDihhk3rgWgi9R0h1wjM+1sgBMo4rp4co0pCbW0yJ0gt6bZY99Bf/X1mymbDThzXMXvxI2mMF52MqqlQk3XowCCinglC9bdfpu+18qTHmaDpXCKPcoyy+M5waoRTepuTJbxiMURuytgoT6Auu04LJPZ204pXzUMFAoIyDI7iv1+K6AQQBcCAwEAAaNSMFAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUam+/bLYpLcOV2ozA42noBkTZyRIwCwYDVR0PBAQDAgEGMBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQsFAAOCAQEAGi0XFj3W3fC/cq2BaiTgpzB4OiYbGjjourf8foTTef0sDOiWol7qwoYhVHLHQgchSdrzj5uBQDewo192ByMa0OZZrtECaaEZo7zW3ny/Oo16pCPgzaY4xpzdU7Ln4fyTftzDHxl81Nqt2GlZDn967/fJPQAiyZJRbFKSjQ0QvyUootkXVhoewHpx8QDDLvWL5GOFTb2o5ZNJCiJYWRwbRD4Sc8AZBkU8y+XQ7EIzVyJhzNfXzwzjFDE8Yw7zMkFjTL/8XuOq6lPPZrpBEOZ/bHHuKh67UBwBlTD9H/hoTcRESuuQlJ3RGUWUEfIiIV5WxrpfdeJpHY/wnaGTTqSruA==")

	// Test with pem encoding, no url encoding

	cfg2 := mtlsforward.CreateConfig()
	cfg2.Headers["sslClientCert"] = "SSL_CLIENT_CERT"
	cfg2.Headers["sslCertChainPrefix"] = "CERT_CHAIN"
	cfg2.EncodePem = true
	cfg2.RemoveNewline = false
	handler2, err := mtlsforward.New(ctx, next, cfg2, "mtlsforward-plugin2")
	if err != nil {
		t.Fatal(err)
	}
	handler2.ServeHTTP(recorder, req)

	assertHeader(t, req, "SSL_CLIENT_CERT", certPEM)
	assertHeader(t, req, "CERT_CHAIN_0", caPEM)

	// Test with base64 encoding, no url encoding

	cfg3 := mtlsforward.CreateConfig()
	cfg3.Headers["sslClientCert"] = "SSL_CLIENT_CERT"
	cfg3.Headers["sslCertChainPrefix"] = "CERT_CHAIN"
	cfg3.EncodePem = true
	cfg3.EncodeURL = true
	handler3, err := mtlsforward.New(ctx, next, cfg3, "mtlsforward-plugin3")
	if err != nil {
		t.Fatal(err)
	}
	handler3.ServeHTTP(recorder, req)

	assertHeader(t, req, "SSL_CLIENT_CERT", "-----BEGIN+CERTIFICATE-----%0AMIIDEDCCAfigAwIBAgIIQXxeH1vM%2BtYwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE%0AAwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQ1MDBaGA85OTk5MTIzMTIzNTk1OVowFjEU%0AMBIGA1UEAwwLbXRsc19jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK%0AAoIBAQDA4g7AcPxzOraD65UYakPOZ8c43E7yBZqcF85ZvfUrN5%2FeOItQUT2Kqw%2FM%0Ax6ynfvliPHbqBaoCmuaJzigS5CJc4x3%2FnuYKKycqJaGXiQJ1i3hEQk%2B04TGdkTs0%0A4kzKkS1PNYOZCX11P%2F3hdQ4DykfxcfqKqvGLCCVGPbyr7C%2BhPzzIkppPJuMOM9oJ%0ASb1AW3a%2BT2uOtI4J1wLq7IqlSyCzMVSzCI9CJ8vGIUe4RGlFR90ONHHYxz5EtkQq%0AlVM27o2zGqT4dPX5XMmAFdjeKIgS6SOAwSJjmLPvdKmvFkweeKqPPNwghjICokzb%0A0TVRorVYWSIGFXiNBQl1QLX2%2FA2FAgMBAAGjZDBiMAwGA1UdEwEB%2FwQCMAAwHQYD%0AVR0OBBYEFC0Po%2F%2BVc34sMuYCOxVL7FOk4yg%2BMAsGA1UdDwQEAwIDuDATBgNVHSUE%0ADDAKBggrBgEFBQcDAjARBglghkgBhvhCAQEEBAMCBaAwDQYJKoZIhvcNAQELBQAD%0AggEBADQHzmjRUsFaT8fiwt0QAh3uX18JVWiKGbC5YC6heBeqfq32TUmIqLDZl9lk%0AhnuI1%2Bw0LTmn415bVz2xJsFmRXBMludH8MhQbkrL1hKSjrlEtF7K5pa3gt8lanEq%0AX2JPLSv2verLZr3ptJ6TI2RfbmdhRU5fEPETfPaf%2B2EkyZ8l6UbbUm7PV6XQsINX%0AGyxAcQq%2FxlonGAhWuAQ23nDP7TF8QmVAiY%2FC8TgidEvYmmWsna0ezOeDM%2Fw7KX6%2B%0AzegYc03Fmul9vlGu9ZP70SNmyVFL%2F%2FLIzXf16rvsMLNeWho5d8Y0usywXjuuS2WE%0ADqH21BZ19OniZNd5kW5xUaF7J0A%3D%0A-----END+CERTIFICATE-----%0A")
	assertHeader(t, req, "CERT_CHAIN_0", "-----BEGIN+CERTIFICATE-----%0AMIIC%2BjCCAeKgAwIBAgIIWNc0nQJTjRcwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE%0AAwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQxMDBaGA85OTk5MTIzMTIzNTk1OVowEjEQ%0AMA4GA1UEAwwHdGVzdF9jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB%0AAMhY4qJQlsihrq7GzZKlXjEadqHUKrP7po6fSaWlI0OQ5vPo%2BNP%2F%2FEDB1aSnra8z%0Af8sXuN6rujQU7aFMe0jV2gat5qFNWxdEDuA42npKXlJZaes3JdBcoLaAftdSxL9d%0AkeTIbqumTR3esN%2Fz6q%2FAYcgm7qbIBSTzVZSwKnDihhk3rgWgi9R0h1wjM%2B1sgBMo%0A4rp4co0pCbW0yJ0gt6bZY99Bf%2FX1mymbDThzXMXvxI2mMF52MqqlQk3XowCCingl%0AC9bdfpu%2B18qTHmaDpXCKPcoyy%2BM5waoRTepuTJbxiMURuytgoT6Auu04LJPZ204p%0AXzUMFAoIyDI7iv1%2BK6AQQBcCAwEAAaNSMFAwDwYDVR0TAQH%2FBAUwAwEB%2FzAdBgNV%0AHQ4EFgQUam%2B%2FbLYpLcOV2ozA42noBkTZyRIwCwYDVR0PBAQDAgEGMBEGCWCGSAGG%0A%2BEIBAQQEAwIABzANBgkqhkiG9w0BAQsFAAOCAQEAGi0XFj3W3fC%2Fcq2BaiTgpzB4%0AOiYbGjjourf8foTTef0sDOiWol7qwoYhVHLHQgchSdrzj5uBQDewo192ByMa0OZZ%0ArtECaaEZo7zW3ny%2FOo16pCPgzaY4xpzdU7Ln4fyTftzDHxl81Nqt2GlZDn967%2FfJ%0APQAiyZJRbFKSjQ0QvyUootkXVhoewHpx8QDDLvWL5GOFTb2o5ZNJCiJYWRwbRD4S%0Ac8AZBkU8y%2BXQ7EIzVyJhzNfXzwzjFDE8Yw7zMkFjTL%2F8XuOq6lPPZrpBEOZ%2FbHHu%0AKh67UBwBlTD9H%2FhoTcRESuuQlJ3RGUWUEfIiIV5WxrpfdeJpHY%2FwnaGTTqSruA%3D%3D%0A-----END+CERTIFICATE-----%0A")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	v := req.Header.Get(key)

	if v == "" {
		t.Errorf("header %s does not exist", key)
	}

	if v != expected {
		t.Errorf("invalid header value: %s for header %s", req.Header.Get(key), key)
	}
}
