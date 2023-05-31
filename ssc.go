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
		Issuer: &CertificatePkixName{
			Country:            ca.Issuer.Country[0],
			Province:           ca.Issuer.Province[0],
			Locality:           ca.Issuer.Locality[0],
			Organization:       ca.Issuer.Organization[0],
			OrganizationalUnit: ca.Issuer.OrganizationalUnit[0],
			StreetAddress:      ca.Issuer.StreetAddress[0],
			PostalCode:         ca.Issuer.PostalCode[0],
			SerialNumber:       "",
			CommonName:         ca.Issuer.CommonName,
		},
		Subject: &CertificatePkixName{
			Country:            ca.Subject.Country[0],
			Province:           ca.Subject.Province[0],
			Locality:           ca.Subject.Locality[0],
			Organization:       ca.Subject.Organization[0],
			OrganizationalUnit: ca.Subject.OrganizationalUnit[0],
			StreetAddress:      ca.Subject.StreetAddress[0],
			PostalCode:         ca.Subject.PostalCode[0],
			SerialNumber:       "",
			CommonName:         ca.Subject.CommonName,
		},
		IPs:      nil,
		Emails:   nil,
		DNSNames: nil,
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(caPEM) {
		err = fmt.Errorf("afssl: append into cert pool failed")
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
