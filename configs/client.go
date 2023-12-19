package configs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/aacfactory/afssl"
	"os"
	"strings"
)

type Client struct {
	CA                 string `json:"ca" yaml:"ca"`
	CAKey              string `json:"caKey" yaml:"caKey"`
	Cert               string `json:"cert" yaml:"cert"`
	Key                string `json:"key" yaml:"key"`
	ServerName         string `json:"serverName" yaml:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify" yaml:"insecureSkipVerify"`
}

func (client *Client) Load() (v *tls.Config, err error) {
	cakey := strings.TrimSpace(client.CAKey)
	if cakey == "" {
		cas := x509.NewCertPool()
		ca := strings.TrimSpace(client.CA)
		if ca != "" {
			caPEM, readCAErr := os.ReadFile(ca)
			if readCAErr != nil {
				err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("read ca failed"), readCAErr)
				return
			}
			cas.AppendCertsFromPEM(caPEM)
		}
		cert := strings.TrimSpace(client.Cert)
		if cert == "" {
			err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("cert is required"))
			return
		}
		certPEM, readCertErr := os.ReadFile(cert)
		if readCertErr != nil {
			err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("read cert failed"), readCertErr)
			return
		}
		key := strings.TrimSpace(client.Key)
		if key == "" {
			err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("key is required"))
			return
		}
		keyPEM, readKeyErr := os.ReadFile(key)
		if readKeyErr != nil {
			err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("read key failed"), readKeyErr)
			return
		}
		certificate, certificateErr := tls.X509KeyPair(certPEM, keyPEM)
		if certificateErr != nil {
			err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("invalid keypair"), certificateErr)
			return
		}
		v = &tls.Config{
			RootCAs:            cas,
			Certificates:       []tls.Certificate{certificate},
			ServerName:         client.ServerName,
			InsecureSkipVerify: client.InsecureSkipVerify,
		}
		return
	}
	ca := strings.TrimSpace(client.CA)
	if ca == "" {
		err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("ca is required"))
		return
	}
	caPEM, readCAErr := os.ReadFile(ca)
	if readCAErr != nil {
		err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("read ca failed"), readCAErr)
		return
	}
	caKeyPEM, readCAKeyErr := os.ReadFile(cakey)
	if readCAKeyErr != nil {
		err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("read cakey failed"), readCAKeyErr)
		return
	}

	block, _ := pem.Decode(caPEM)
	caCert, parseCAErr := x509.ParseCertificate(block.Bytes)
	if parseCAErr != nil {
		err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("parse ca failed"), parseCAErr)
		return
	}

	config := afssl.CertificateConfig{
		Subject: &afssl.CertificatePkixName{
			Country:            caCert.Subject.Country[0],
			Province:           caCert.Subject.Province[0],
			Locality:           caCert.Subject.Locality[0],
			Organization:       caCert.Subject.Organization[0],
			OrganizationalUnit: caCert.Subject.OrganizationalUnit[0],
			CommonName:         caCert.Subject.CommonName,
		},
		IPs:      nil,
		Emails:   nil,
		DNSNames: nil,
	}

	certPEM, keyPEM, createClientErr := afssl.GenerateCertificate(config, afssl.WithParent(caPEM, caKeyPEM))
	if createClientErr != nil {
		err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("generate by ca failed"), createClientErr)
		return
	}
	certificate, certificateErr := tls.X509KeyPair(certPEM, keyPEM)
	if certificateErr != nil {
		err = errors.Join(errors.New("afssl: load client tls failed"), errors.New("invalid keypair"), certificateErr)
		return
	}
	cas := x509.NewCertPool()
	cas.AppendCertsFromPEM(caPEM)
	v = &tls.Config{
		RootCAs:            cas,
		Certificates:       []tls.Certificate{certificate},
		ServerName:         client.ServerName,
		InsecureSkipVerify: client.InsecureSkipVerify,
	}
	return
}
