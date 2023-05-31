package afssl

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"github.com/aacfactory/afssl/gmsm/tlcp"
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

func WithKeyType(keyType KeyType) GenerateCertificateOption {
	return func(options *GenerateCertificateOptions) error {
		options.keyType = keyType
		return nil
	}
}

func WithParent(certPEM []byte, keyPEM []byte) GenerateCertificateOption {
	return func(options *GenerateCertificateOptions) error {
		key, keyType, parseKeyErr := ParsePrivateKey(keyPEM)
		if parseKeyErr != nil {
			return parseKeyErr
		}
		options.keyType = keyType
		options.parentKey = key
		certBlock, _ := pem.Decode(certPEM)
		if certBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid cert pem")
		}
		switch keyType.Name() {
		case sm2KeyTypeName, sm9KeyTypeName:
			cert, parseCertErr := smx509.ParseCertificate(certBlock.Bytes)
			if parseCertErr != nil {
				return parseCertErr
			}
			options.parent = cert
			break
		default:
			cert, parseCertErr := x509.ParseCertificate(certBlock.Bytes)
			if parseCertErr != nil {
				return parseCertErr
			}
			options.parent = cert
		}
		return nil
	}
}

type GenerateCertificateOptions struct {
	keyType      KeyType
	serialNumber *big.Int
	expire       time.Duration
	isCA         bool
	parent       any
	parentKey    any
}

type CertificatePkixName struct {
	Country            string
	Province           string
	Locality           string
	Organization       string
	OrganizationalUnit string
	StreetAddress      string
	PostalCode         string
	SerialNumber       string
	CommonName         string
}

func (pn *CertificatePkixName) Name() pkix.Name {
	return pkix.Name{
		Country:            []string{strings.TrimSpace(pn.Country)},
		Organization:       []string{strings.TrimSpace(pn.Organization)},
		OrganizationalUnit: []string{strings.TrimSpace(pn.OrganizationalUnit)},
		Locality:           []string{strings.TrimSpace(pn.Locality)},
		Province:           []string{strings.TrimSpace(pn.Province)},
		StreetAddress:      []string{strings.TrimSpace(pn.StreetAddress)},
		PostalCode:         []string{strings.TrimSpace(pn.PostalCode)},
		SerialNumber:       strings.TrimSpace(pn.SerialNumber),
		CommonName:         strings.TrimSpace(pn.CommonName),
		Names:              nil,
		ExtraNames:         nil,
	}
}

type CertificateConfig struct {
	Issuer   *CertificatePkixName
	Subject  *CertificatePkixName
	IPs      []string
	Emails   []string
	DNSNames []string
}

var defaultPkixName = &CertificatePkixName{
	Country:            "CN",
	Province:           "",
	Organization:       "FNS",
	OrganizationalUnit: "",
	StreetAddress:      "",
	PostalCode:         "",
	SerialNumber:       "",
	CommonName:         "AFSSL",
}

func GenerateCertificate(config CertificateConfig, opts ...GenerateCertificateOption) (certPEM []byte, keyPEM []byte, err error) {
	// SN
	serialNumber, randSNErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if randSNErr != nil {
		err = fmt.Errorf("afssl: generate certificate failed, rand serial number failed, %v", randSNErr)
		return
	}
	// OPT
	opt := &GenerateCertificateOptions{
		keyType:      ECDSA(),
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
				err = fmt.Errorf("afssl: generate certificate failed, %v", optErr)
				return
			}
		}
	}
	// KEY
	var key any
	var isGM bool
	var signatureAlgorithm int
	var pub any
	switch opt.keyType.Name() {
	case rsaKeyTypeName:
		kt := opt.keyType.(*rsaKeyType)
		key, err = rsa.GenerateKey(rand.Reader, kt.keyBits)
		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
		signatureAlgorithm = int(x509.SHA256WithRSA)
		pub = &(key.(*rsa.PrivateKey).PublicKey)
		break
	case ecdsaKeyTypeName:
		kt := opt.keyType.(*ecdsaKeyType)
		key, err = ecdsa.GenerateKey(kt.curve, rand.Reader)
		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
		signatureAlgorithm = int(x509.ECDSAWithSHA256)
		pub = &(key.(*ecdsa.PrivateKey).PublicKey)
		break
	case ed25519KeyTypeName:
		kt := opt.keyType.(*ed25519KeyType)
		if len(kt.seed) == 0 {
			_, key, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				err = fmt.Errorf("afssl: generate certificate failed, %v", err)
				return
			}
		} else {
			key = ed25519.NewKeyFromSeed(kt.seed)
		}
		signatureAlgorithm = int(x509.PureEd25519)
		pub = key.(*ed25519.PrivateKey).Public()
		break
	case sm2KeyTypeName:
		key, err = sm2.GenerateKey(rand.Reader)
		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
		isGM = true
		signatureAlgorithm = int(smx509.SM2WithSM3)
		pub = &(key.(*sm2.PrivateKey).PublicKey)
		break
	default:
		err = fmt.Errorf("afssl: generate certificate failed, key type is not supported")
		return
	}
	var keyDER []byte
	if isGM {
		keyDER, err = smx509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
	} else {
		keyDER, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
	}

	issuer := defaultPkixName
	if config.Issuer != nil {
		issuer = config.Issuer
	}
	subject := defaultPkixName
	if config.Subject != nil {
		subject = config.Subject
	}

	// CERT
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

	var certDER []byte
	if isGM {
		cert := &smx509.Certificate{
			Signature:             nil,
			SignatureAlgorithm:    x509.SignatureAlgorithm(signatureAlgorithm),
			PublicKey:             pub,
			Version:               0,
			SerialNumber:          serialNumber,
			Issuer:                issuer.Name(),
			Subject:               subject.Name(),
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(opt.expire),
			KeyUsage:              ku,
			Extensions:            []pkix.Extension{},
			ExtraExtensions:       []pkix.Extension{},
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
			parent = opt.parent.(*smx509.Certificate)
			parentKey = opt.parentKey
		}

		certDER, err = smx509.CreateCertificate(rand.Reader, cert, parent, pub, parentKey)

		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
	} else {
		cert := &x509.Certificate{
			Signature:          nil,
			SignatureAlgorithm: x509.SignatureAlgorithm(signatureAlgorithm),
			PublicKey:          pub,
			Version:            0,
			SerialNumber:       serialNumber,
			Issuer:             issuer.Name(),
			Subject:            subject.Name(),
			NotBefore:          time.Now().Add(-24 * time.Hour),
			NotAfter:           time.Now().Add(opt.expire),
			KeyUsage:           ku,
			Extensions:         []pkix.Extension{},
			//ExtraExtensions: []pkix.Extension{{
			//	Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44},
			//	Critical: false,
			//	Value:    []byte{0x05, 0x00}, // ASN.1 NULL
			//}},
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
			parent = opt.parent.(*x509.Certificate)
			parentKey = opt.parentKey
		}

		certDER, err = x509.CreateCertificate(rand.Reader, cert, parent, pub, parentKey)
		if err != nil {
			err = fmt.Errorf("afssl: generate certificate failed, %v", err)
			return
		}
	}
	// PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	// verify
	if isGM {
		_, err = tlcp.X509KeyPair(certPEM, keyPEM)
	} else {
		_, err = tls.X509KeyPair(certPEM, keyPEM)
	}
	if err != nil {
		err = fmt.Errorf("afssl: generate certificate failed, %v", err)
		return
	}
	return
}
