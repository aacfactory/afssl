package configs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/aacfactory/afssl"
	"os"
	"strings"
)

type Server struct {
	CA         string `json:"ca" yaml:"ca"`
	CAKey      string `json:"caKey" yaml:"caKey"`
	Cert       string `json:"cert" yaml:"cert"`
	Key        string `json:"key" yaml:"key"`
	ClientAuth string `json:"clientAuth" yaml:"clientAuth"`
}

func (server *Server) getClientAuth() (v tls.ClientAuthType) {
	switch strings.TrimSpace(strings.ToLower(server.ClientAuth)) {
	case "no_client_cert":
		v = tls.NoClientCert
		break
	case "request_client_cert":
		v = tls.RequestClientCert
		break
	case "require_and_client_cert":
		v = tls.RequireAnyClientCert
		break
	case "verify_client_cert_if_given":
		v = tls.VerifyClientCertIfGiven
		break
	case "require_and_verify_client_cert":
		v = tls.RequireAndVerifyClientCert
		break
	default:
		v = tls.NoClientCert
		break
	}
	return
}

func (server *Server) Load() (v *tls.Config, err error) {
	cakey := strings.TrimSpace(server.CAKey)
	if cakey == "" {
		cas := x509.NewCertPool()
		ca := strings.TrimSpace(server.CA)
		if ca != "" {
			caPEM, readCAErr := os.ReadFile(ca)
			if readCAErr != nil {
				err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("read ca failed"), readCAErr)
				return
			}
			cas.AppendCertsFromPEM(caPEM)
		}
		cert := strings.TrimSpace(server.Cert)
		if cert == "" {
			err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("cert is required"))
			return
		}
		certPEM, readCertErr := os.ReadFile(cert)
		if readCertErr != nil {
			err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("read cert failed"), readCertErr)
			return
		}
		key := strings.TrimSpace(server.Key)
		if key == "" {
			err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("key is required"))
			return
		}
		keyPEM, readKeyErr := os.ReadFile(key)
		if readKeyErr != nil {
			err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("read key failed"), readKeyErr)
			return
		}
		certificate, certificateErr := tls.X509KeyPair(certPEM, keyPEM)
		if certificateErr != nil {
			err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("invalid keypair"), certificateErr)
			return
		}
		v = &tls.Config{
			ClientCAs:    cas,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   server.getClientAuth(),
		}
		return
	}
	ca := strings.TrimSpace(server.CA)
	if ca == "" {
		err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("ca is required"))
		return
	}
	caPEM, readCAErr := os.ReadFile(ca)
	if readCAErr != nil {
		err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("read ca failed"), readCAErr)
		return
	}
	caKeyPEM, readCAKeyErr := os.ReadFile(cakey)
	if readCAKeyErr != nil {
		err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("read cakey failed"), readCAKeyErr)
		return
	}

	config := afssl.CertificateConfig{}
	certPEM, keyPEM, createClientErr := afssl.GenerateCertificate(config, afssl.WithParent(caPEM, caKeyPEM))
	if createClientErr != nil {
		err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("generate by ca failed"), createClientErr)
		return
	}
	certificate, certificateErr := tls.X509KeyPair(certPEM, keyPEM)
	if certificateErr != nil {
		err = errors.Join(errors.New("afssl: load server tls failed"), errors.New("invalid keypair"), certificateErr)
		return
	}
	cas := x509.NewCertPool()
	cas.AppendCertsFromPEM(caPEM)
	v = &tls.Config{
		ClientCAs:    cas,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   server.getClientAuth(),
	}
	return
}
