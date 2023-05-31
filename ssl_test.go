package afssl_test

import (
	"fmt"
	"github.com/aacfactory/afssl"
	"testing"
)

func TestGenerateCertificate(t *testing.T) {
	config := afssl.CertificateConfig{}
	// ca
	caPEM, caKeyPEM, caErr := afssl.GenerateCertificate(config, afssl.CA(), afssl.WithKeyType(afssl.SM2()))
	if caErr != nil {
		t.Error("ca", caErr)
		return
	}
	fmt.Println(string(caPEM))
	fmt.Println(string(caKeyPEM))
	// server
	serverPEM, serverKeyPEM, serverErr := afssl.GenerateCertificate(config, afssl.WithParent(caPEM, caKeyPEM))
	if serverErr != nil {
		t.Error("server", serverErr)
		return
	}
	fmt.Println(string(serverPEM))
	fmt.Println(string(serverKeyPEM))
	// client
	clientPEM, clientKeyPEM, clientErr := afssl.GenerateCertificate(config, afssl.WithParent(caPEM, caKeyPEM))
	if clientErr != nil {
		t.Error("client", clientErr)
		return
	}
	fmt.Println(string(clientPEM))
	fmt.Println(string(clientKeyPEM))
}
