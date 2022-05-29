package afssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type GenerateCertificateOption func(*GenerateCertificateOptions) error

func WithSerialNumber(sn uint64) GenerateCertificateOption {
	return func(options *GenerateCertificateOptions) error {
		if sn < 1 {
			return fmt.Errorf("invalid serial number")
		}
		options.serialNumber.SetUint64(sn)
		return nil
	}
}

func CA() GenerateCertificateOption {
	return func(options *GenerateCertificateOptions) error {
		options.isCA = true
		return nil
	}
}

func WithExpirationDays(days int) GenerateCertificateOption {
	return func(options *GenerateCertificateOptions) error {
		if days < 1 {
			return fmt.Errorf("invalid expiration days")
		}
		options.expire = time.Duration(days) * 24 * time.Hour
		return nil
	}
}

func WithParent(certPEM []byte, keyPEM []byte) GenerateCertificateOption {
	return func(options *GenerateCertificateOptions) error {
		certBlock, _ := pem.Decode(certPEM)
		if certBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid cert")
		}
		cert, parseCertErr := x509.ParseCertificate(certBlock.Bytes)
		if parseCertErr != nil {
			return parseCertErr
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock.Type != "RSA PRIVATE KEY" {
			return fmt.Errorf("invalid key")
		}
		key, parseKeyErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if parseKeyErr != nil {
			return parseKeyErr
		}
		options.parent = cert
		options.parentKey = key
		return nil
	}
}

type GenerateCertificateOptions struct {
	serialNumber *big.Int
	expire       time.Duration
	isCA         bool
	parent       *x509.Certificate
	parentKey    *rsa.PrivateKey
}

type CertificateConfig struct {
	Country            string
	Province           string
	City               string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	IPs                []string
	Emails             []string
	DNSNames           []string
}

func GenerateCertificate(config CertificateConfig, opts ...GenerateCertificateOption) (certPEM []byte, keyPEM []byte, err error) {
	// RSA KEY
	key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		err = fmt.Errorf("generate certificate failed, %v", keyErr)
		return
	}
	// SN
	serialNumber, randSNErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if randSNErr != nil {
		err = fmt.Errorf("generate certificate failed, rand serial number failed, %v", randSNErr)
		return
	}
	// OPT
	opt := &GenerateCertificateOptions{
		serialNumber: serialNumber,
		expire:       365 * 24 * time.Hour,
		isCA:         false,
		parent:       nil,
		parentKey:    nil,
	}
	if opts != nil {
		for _, option := range opts {
			optErr := option(opt)
			if optErr != nil {
				err = fmt.Errorf("generate certificate failed, %v", optErr)
				return
			}
		}
	}
	ips := make([]net.IP, 0, 1)
	if config.IPs != nil {
		for _, e := range config.IPs {
			if ip := net.ParseIP(e); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	basicConstraintsValid := false
	ku := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if opt.isCA {
		ku = ku | x509.KeyUsageCertSign
		basicConstraintsValid = true
	}
	// CERT
	cert := &x509.Certificate{
		Signature:          nil,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &key.PublicKey,
		Version:            0,
		SerialNumber:       serialNumber,
		Issuer:             pkix.Name{},
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
		NotBefore:  time.Now().Add(-24 * time.Hour),
		NotAfter:   time.Now().Add(opt.expire),
		KeyUsage:   ku,
		Extensions: []pkix.Extension{},
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44},
			Critical: false,
			Value:    []byte{0x05, 0x00}, // ASN.1 NULL
		}},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: basicConstraintsValid,
		IsCA:                  opt.isCA,
		DNSNames:              config.DNSNames,
		EmailAddresses:        config.Emails,
		IPAddresses:           ips,
	}

	parent := cert
	parentKey := key
	if opt.parent != nil {
		parent = opt.parent
		parentKey = opt.parentKey
	}

	certRaw, certErr := x509.CreateCertificate(rand.Reader, cert, parent, &key.PublicKey, parentKey)
	if certErr != nil {
		err = fmt.Errorf("generate certificate failed, %v", certErr)
		return
	}
	// PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return
}
