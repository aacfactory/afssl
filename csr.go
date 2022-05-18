package afssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"strings"
)

func generateCSR(key *rsa.PrivateKey, config Config) (csr *x509.CertificateRequest, err error) {
	csr = &x509.CertificateRequest{
		SignatureAlgorithm: signerAlgo(key),
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &key.PublicKey,
		Subject: pkix.Name{
			Country:            []string{strings.TrimSpace(config.Country)},
			Organization:       []string{strings.TrimSpace(config.Organization)},
			OrganizationalUnit: []string{strings.TrimSpace(config.OrganizationalUnit)},
			Locality:           []string{strings.TrimSpace(config.City)},
			Province:           []string{strings.TrimSpace(config.Province)},
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       "",
			CommonName:         strings.TrimSpace(config.CommonName),
			Names:              nil,
			ExtraNames:         nil,
		},
		Extensions:      nil,
		ExtraExtensions: nil,
		DNSNames:        nil,
		EmailAddresses:  nil,
		IPAddresses:     make([]net.IP, 0, 1),
		URIs:            nil,
	}
	if config.IPs != nil {
		for _, e := range config.IPs {
			if ip := net.ParseIP(e); ip != nil {
				csr.IPAddresses = append(csr.IPAddresses, ip)
			}
		}
	}
	csr.ExtraExtensions = []pkix.Extension{}
	if config.DelegationEnabled {
		csr.ExtraExtensions = append(csr.Extensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44},
			Critical: false,
			Value:    []byte{0x05, 0x00}, // ASN.1 NULL
		})
	}
	//if err = csr.CheckSignature(); err != nil {
	//	err = fmt.Errorf("generate certificate request failed, %v", err)
	//	return
	//}
	return
}

func encodeCSR(key *rsa.PrivateKey, csr *x509.CertificateRequest) (csrPEM []byte, err error) {
	csrRaw, csrErr := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if csrErr != nil {
		err = csrErr
		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrRaw,
	}
	csrPEM = pem.EncodeToMemory(&block)
	return
}
