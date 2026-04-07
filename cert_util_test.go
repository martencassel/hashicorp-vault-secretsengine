package kfbackend

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	assert "github.com/stretchr/testify/assert"
)

func TestSubmitCSR(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{
            "CertificateInformation": {
                "Certificates": ["-----BEGIN CERTIFICATE-----FAKE-----END CERTIFICATE-----"],
                "SerialNumber": "1234",
                "KeyfactorID": 42
            }
        }`)
	}))
	defer ts.Close()

	storage := &logical.InmemStorage{}
	cfg := &keyfactorConfig{
		KeyfactorUrl:   ts.URL,
		CommandAPIPath: "Command",
	}
	entry, _ := logical.StorageEntryJSON("config", cfg)
	storage.Put(context.Background(), entry)

	b := backend()

	b.httpClientOverride = ts.Client() // <-- the magic

	certs, serial, err := b.submitCSR(
		context.Background(),
		&logical.Request{Storage: storage},
		"csr",
		"CA",
		"Template",
		nil,
		nil,
		"{}",
	)

	if err != nil {
		t.Fatal(err)
	}
	if serial != "1234" {
		t.Fatalf("unexpected serial: %s", serial)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert")
	}
}

func TestCSRFromPrivateKey(t *testing.T) {
	// Instantiate the backend (keyfactorBackend)
	b := backend()
	// Define test parameters for the CSR generation
	cn := "test.example.com"
	ip_sans := []string{"10.0.0.1", "10.0.0.2"}
	dns_sans := []string{"example.com", "www.example.com"}
	// Call the GenerateCSR function with the test parameters
	csr, privKey := b.generateCSR(cn, ip_sans, dns_sans)
	assert.NotEmpty(t, csr, "CSR should not be empty")
	assert.NotEmpty(t, privKey, "Private key should not be empty")

	// Parse the generated CSR to verify its contents
	parsedCSR, err := ParseCSR(csr)
	assert.NoError(t, err, "Parsing CSR should not produce an error")
	assert.Equal(t, cn, parsedCSR.Subject.CommonName, "Common Name should match")
	for i, ip := range ip_sans {
		assert.Equal(t, ip, parsedCSR.IPAddresses[i].String(), "IP SAN should match")
	}
	for i, dns := range dns_sans {
		assert.Equal(t, dns, parsedCSR.DNSNames[i], "DNS SAN should match")
	}
}

func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("failed to decode PEM block containing CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	return csr, nil
}

func TestFetchCAInfo(t *testing.T) {
	var method string
	var path string
	var rawQuery string
	var requestedWith string
	var contentType string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		rawQuery = r.URL.RawQuery
		requestedWith = r.Header.Get("x-keyfactor-requested-with")
		contentType = r.Header.Get("content-type")

		fmt.Fprintf(w, `[]`)
	}))
	defer ts.Close()

	storage := &logical.InmemStorage{}
	cfg := &keyfactorConfig{
		KeyfactorUrl:   ts.URL,
		CommandAPIPath: "Command",
	}
	entry, _ := logical.StorageEntryJSON("config", cfg)
	storage.Put(context.Background(), entry)

	b := backend()
	b.httpClientOverride = ts.Client() // <-- the magic
	resp, err := fetchCAInfo(context.Background(), &logical.Request{Storage: storage}, b, "TestCA", true)
	assert.Nil(t, resp, "Response should be nil when no issued cert exists")
	assert.Error(t, err, "Expected fetchCAInfo to fail when CA has no issued certificates")
	assert.Contains(t, err.Error(), "no certificates issued by CA TestCA found in Command")

	assert.Equal(t, "GET", method)
	assert.Equal(t, "/Command/Certificates", path)
	assert.Equal(t, "pq.queryString=CA%20-eq%20%22TestCA%20%22&ReturnLimit=1", rawQuery)
	assert.Equal(t, "APIClient", requestedWith)
	assert.Equal(t, "application/json", contentType)
}

func TestFetchCertIssuedByCA(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/Command/Certificates", r.URL.Path)
		assert.Equal(t, "pq.queryString=CA%20-eq%20%22TestCA%20%22&ReturnLimit=1", r.URL.RawQuery)
		assert.Equal(t, "APIClient", r.Header.Get("x-keyfactor-requested-with"))
		assert.Equal(t, "application/json", r.Header.Get("content-type"))

		fmt.Fprintf(w, `[
			{
				"Id": 42,
				"CertificateAuthorityName": "TestCA"
			}
		]`)
	}))
	defer ts.Close()

	storage := &logical.InmemStorage{}
	cfg := &keyfactorConfig{
		KeyfactorUrl:   ts.URL,
		CommandAPIPath: "Command",
	}
	entry, _ := logical.StorageEntryJSON("config", cfg)
	storage.Put(context.Background(), entry)

	b := backend()
	b.httpClientOverride = ts.Client()

	resp, err := fetchCertIssuedByCA(context.Background(), &logical.Request{Storage: storage}, b, "TestCA")
	assert.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, 42, resp[0].ID)
}

// func fetchCertBySerial(ctx context.Context, req *logical.Request, prefix, serial string) (*logical.StorageEntry, error) {

func TestFetchCertBySerial(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/Command/Certificates", r.URL.Path)
		assert.Equal(t, "pq.queryString=Serial%20-eq%20%221234%22&ReturnLimit=1", r.URL.RawQuery)
		assert.Equal(t, "APIClient", r.Header.Get("x-keyfactor-requested-with"))
		assert.Equal(t, "application/json", r.Header.Get("content-type"))

		fmt.Fprintf(w, `[
			{
				"Id": 42,
				"SerialNumber": "1234"
			}
		]`)
	}))
	defer ts.Close()

	storage := &logical.InmemStorage{}
	cfg := &keyfactorConfig{
		KeyfactorUrl:   ts.URL,
		CommandAPIPath: "Command",
	}
	entry, _ := logical.StorageEntryJSON("config", cfg)
	storage.Put(context.Background(), entry)

	// CertEntry should be returned with the correct key and no error
	storage.Put(context.Background(), &logical.StorageEntry{
		Key:   "certs/1234",
		Value: []byte("fake-cert-data"),
	})

	b := backend()
	b.httpClientOverride = ts.Client()

	resp, err := fetchCertBySerial(context.Background(), &logical.Request{Storage: storage}, "certs", "1234")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "certs/1234", resp.Key)
}

// func fetchCertIssuedByCA(ctx context.Context, req *logical.Request, b *keyfactorBackend, caName string) (KeyfactorCertResponse, error) {

func TestFetchCertIssuedByCA_WithCerts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/Command/Certificates", r.URL.Path)
		assert.Equal(t, "pq.queryString=CA%20-eq%20%22TestCA%20%22&ReturnLimit=1", r.URL.RawQuery)
		assert.Equal(t, "APIClient", r.Header.Get("x-keyfactor-requested-with"))
		assert.Equal(t, "application/json", r.Header.Get("content-type"))

		fmt.Fprintf(w, `[
			{
				"Id": 42,
				"CertificateAuthorityName": "TestCA",
				"Certificates": ["-----BEGIN CERTIFICATE-----FAKE-----END CERTIFICATE-----"]
			}
		]`)

	}))
	defer ts.Close()

	storage := &logical.InmemStorage{}
	cfg := &keyfactorConfig{
		KeyfactorUrl:   ts.URL,
		CommandAPIPath: "Command",
	}
	entry, _ := logical.StorageEntryJSON("config", cfg)
	storage.Put(context.Background(), entry)

	b := backend()
	b.httpClientOverride = ts.Client()

	resp, err := fetchCertIssuedByCA(context.Background(), &logical.Request{Storage: storage}, b, "TestCA")
	assert.NoError(t, err)
	assert.Len(t, resp, 1)

}

// func fetchChainAndCAForCert(ctx context.Context, req *logical.Request, b *keyfactorBackend, kfCertId int) ([]string, string, error) {

func TestFetchChainAndCAForCert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/Command/Certificates/42/Chain", r.URL.Path)
		assert.Equal(t, "APIClient", r.Header.Get("x-keyfactor-requested-with"))
		assert.Equal(t, "application/json", r.Header.Get("content-type"))

		fmt.Fprintf(w, `{
			"CertificateChain": ["-----BEGIN CERTIFICATE-----FAKE-----END CERTIFICATE-----"],
			"CertificateAuthority": "TestCA"
		}`)
	}))
	defer ts.Close()

	storage := &logical.InmemStorage{}
	cfg := &keyfactorConfig{
		KeyfactorUrl:   ts.URL,
		CommandAPIPath: "Command",
	}
	entry, _ := logical.StorageEntryJSON("config", cfg)
	storage.Put(context.Background(), entry)
	b := backend()
	b.httpClientOverride = ts.Client()
	chain, ca, err := fetchChainAndCAForCert(context.Background(), &logical.Request{Storage: storage}, b, 42)
	assert.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, "TestCA", ca)
}

func TestNormalizeSerial(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no leading zeros", "1234", "1234"},
		{"leading zeros", "00001234", "1234"},
		{"all zeros", "0000", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeSerial(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertBase64P7BtoCertificates(t *testing.T) {
	// This is a base64-encoded PKCS#7 structure containing a single certificate
	base64P7B := "MIIGQwIBAzCCBkmgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxHjAcBgNVBAoTFUxlbmdlbmRhIEJlbm5ldHQgSW5jMQswCQYDVQQLEwJJVDESMBAGA1UECxMJQ2VydGlmaWNhdGlvbjEyMDAGA1UEAxMpTGVuZ2VuZGEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBSU0EgLSBTSEEyNTYgLSBDQSAtIEcyMB4XDT"
	x509Cert, err := ConvertBase64P7BtoCertificates(base64P7B)
	assert.NoError(t, err)
	assert.Len(t, x509Cert, 1)
	assert.Equal(t, "CN=Test Certificate, OU=Certification, O=Lengenda Bennet Inc, L=Seattle, ST=Washington, C=US", x509Cert[0].Subject.String())
}

func TestConvertBase64P7BtoPEM(t *testing.T) {
	base64P7B := "MIIGQwIBAzCCBkmgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxHjAcBgNVBAoTFUxlbmdlbmRhIEJlbm5ldHQgSW5jMQswCQYDVQQLEwJJVDESMBAGA1UECxMJQ2VydGlmaWNhdGlvbjEyMDAGA1UEAxMpTGVuZ2VuZGEgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBSU0EgLSBTSEEyNTYgLSBDQSAtIEcyMB4XDT"
	pemCerts, err := ConvertBase64P7BtoPEM(base64P7B)
	assert.NoError(t, err)
	assert.Len(t, pemCerts, 1)
	assert.Contains(t, pemCerts[0], "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pemCerts[0], "-----END CERTIFICATE-----")
}
