package afssl

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func SSC(caPEM []byte, keyPEM []byte) (serverTLS *tls.Config, clientTLS *tls.Config, err error) {
	config := CertificateConfig{}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(caPEM) {
		err = fmt.Errorf("afssl: append into cert pool failed")
		return
	}
	// server
	serverCert, serverKey, createServerErr := GenerateCertificate(config, WithParent(caPEM, keyPEM))
	if createServerErr != nil {
		err = createServerErr
		return
	}
	serverCertificate, serverCertificateErr := tls.X509KeyPair(serverCert, serverKey)
	if serverCertificateErr != nil {
		err = serverCertificateErr
		return
	}
	serverTLS = &tls.Config{
		ClientCAs:    cas,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	// client
	clientCert, clientKey, createClientErr := GenerateCertificate(config, WithParent(caPEM, keyPEM))
	if createClientErr != nil {
		err = createClientErr
		return
	}
	clientCertificate, clientCertificateErr := tls.X509KeyPair(clientCert, clientKey)
	if clientCertificateErr != nil {
		err = clientCertificateErr
		return
	}
	clientTLS = &tls.Config{
		RootCAs:            cas,
		Certificates:       []tls.Certificate{clientCertificate},
		InsecureSkipVerify: true,
	}
	return
}

func CreateCA(cn string, expireDays int) (crtPEM []byte, keyPEM []byte, err error) {
	if cn == "" {
		cn = "AFSSL"
	}
	if expireDays < 1 {
		expireDays = 3650
	}
	crtPEM, keyPEM, err = GenerateCertificate(CertificateConfig{
		Subject: &CertificatePkixName{
			Country:      "CN",
			Organization: "FNS",
			CommonName:   cn,
		},
	}, CA(), WithExpirationDays(expireDays))
	return
}
