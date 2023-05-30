package smx509_test

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {

	// SN
	serialNumber, randSNErr := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if randSNErr != nil {
		t.Fatal(randSNErr)
		return
	}
	// key
	key, keyErr := sm2.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	// CERT
	cert := &smx509.Certificate{
		Signature:          nil,
		SignatureAlgorithm: smx509.SM2WithSM3,
		PublicKeyAlgorithm: 0,
		PublicKey:          &key.PublicKey,
		Version:            0,
		SerialNumber:       serialNumber,
		Issuer:             pkix.Name{},
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"ORG"},
			OrganizationalUnit: []string{},
			Locality:           []string{},
			Province:           []string{},
			StreetAddress:      nil,
			PostalCode:         nil,
			SerialNumber:       "",
			CommonName:         "CN",
			Names:              nil,
			ExtraNames:         nil,
		},
		NotBefore:  time.Now().Add(-24 * time.Hour),
		NotAfter:   time.Now().Add(24 * time.Hour),
		KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		Extensions: []pkix.Extension{},
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44},
			Critical: false,
			Value:    []byte{0x05, 0x00}, // ASN.1 NULL
		}},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              nil,
		EmailAddresses:        nil,
		IPAddresses:           make([]net.IP, 0, 1),
	}

	certRaw, certErr := smx509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if certErr != nil {
		t.Fatal(certErr)
		return
	}
	// PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	})

	keyDer, keyDerErr := smx509.MarshalPKCS8PrivateKey(key)
	if keyDerErr != nil {
		t.Fatal(keyDerErr)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDer,
	})

	key1Der, key1DerErr := smx509.MarshalSM2PrivateKey(key)
	if key1DerErr != nil {
		t.Fatal(key1DerErr)
		return
	}
	key1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "SM2 PRIVATE KEY",
		Bytes: key1Der,
	})

	fmt.Println(string(certPEM))
	fmt.Println(string(keyPEM))
	fmt.Println(string(key1PEM))

	kp, _ := pem.Decode(key1PEM)
	k, parseKErr := smx509.ParseSM2PrivateKey(kp.Bytes)
	if parseKErr != nil {
		t.Fatal(parseKErr)
	}
	fmt.Println(reflect.TypeOf(k))
	//sk := k.(*sm2.PrivateKey)
	sk := k
	cp, _ := pem.Decode(certPEM)
	c, parseCErr := smx509.ParseCertificate(cp.Bytes)
	if parseCErr != nil {
		t.Fatal(parseCErr)
	}
	fmt.Println(c.PublicKeyAlgorithm)
	fmt.Println(reflect.TypeOf(c.PublicKey))
	fmt.Println(sk.PublicKey.Equal(c.PublicKey))
}
