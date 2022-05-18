package afssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func generateKEY(bits int) (key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		err = fmt.Errorf("generate rsa key pair failed, %v", err)
	}
	return
}

func encodeKEY(key *rsa.PrivateKey) (privatePEM []byte, publicPEM []byte) {
	privatePEM = pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	})
	publicPEM = pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PublicKey(&key.PublicKey),
	})
	return
}

func signerAlgo(key *rsa.PrivateKey) x509.SignatureAlgorithm {
	bitLength := key.PublicKey.N.BitLen()
	switch {
	case bitLength >= 4096:
		return x509.SHA512WithRSA
	case bitLength >= 3072:
		return x509.SHA384WithRSA
	case bitLength >= 2048:
		return x509.SHA256WithRSA
	default:
		return x509.SHA1WithRSA
	}
}
