package kfbackend

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	assert "github.com/stretchr/testify/assert"
)

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
