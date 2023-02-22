package afssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

func SSC(caPEM []byte, keyPEM []byte) (serverTLS *tls.Config, clientTLS *tls.Config, err error) {
	block, _ := pem.Decode(caPEM)
	ca, parseCaErr := x509.ParseCertificate(block.Bytes)
	if parseCaErr != nil {
		err = parseCaErr
		return
	}
	config := CertificateConfig{
		Country:            ca.Subject.Country[0],
		Province:           ca.Subject.Province[0],
		City:               ca.Subject.Locality[0],
		Organization:       ca.Subject.Organization[0],
		OrganizationalUnit: ca.Subject.OrganizationalUnit[0],
		CommonName:         ca.Subject.CommonName,
		IPs:                nil,
		Emails:             nil,
		DNSNames:           nil,
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(caPEM) {
		err = fmt.Errorf("append into cert pool failed")
		return
	}
	// server
	serverCert, serverKey, createServerErr := GenerateCertificate(config, WithParent(caPEM, keyPEM), WithExpirationDays(int(ca.NotAfter.Sub(time.Now()).Hours())/24))
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
	clientCert, clientKey, createClientErr := GenerateCertificate(config, WithParent(caPEM, keyPEM), WithExpirationDays(int(ca.NotAfter.Sub(time.Now()).Hours())/24))
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
	if expireDays < 1 {
		expireDays = 3650
	}
	crtPEM, keyPEM, err = GenerateCertificate(CertificateConfig{
		Country:            "",
		Province:           "",
		City:               "",
		Organization:       "",
		OrganizationalUnit: "",
		CommonName:         cn,
		IPs:                nil,
		Emails:             nil,
		DNSNames:           nil,
	}, CA(), WithExpirationDays(expireDays))
	return
}
