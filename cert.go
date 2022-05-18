package afssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func generateCRT(key *rsa.PrivateKey, csr *x509.CertificateRequest, expire time.Duration, ca bool) (crt *x509.Certificate, err error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, randErr := rand.Int(rand.Reader, max)
	if randErr != nil {
		err = fmt.Errorf("generate certificate failed, %v", randErr)
		return
	}
	crt = &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: signerAlgo(key),
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(expire),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:               ca,
	}
	return
}

func encodeCRT(key *rsa.PrivateKey, tpl *x509.Certificate, parent *x509.Certificate) (csrPEM []byte, err error) {
	crtRaw, crtErr := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, key)
	if crtErr != nil {
		err = crtErr
		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtRaw,
	}
	csrPEM = pem.EncodeToMemory(&block)
	return
}
