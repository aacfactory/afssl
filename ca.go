package afssl

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func generateCA(config Config) (crt *x509.Certificate, key *rsa.PrivateKey, err error) {
	key, err = generateKEY(config.KeyBits)
	if err != nil {
		err = fmt.Errorf("generate ca failed, %v", err)
		return
	}
	csr, csrErr := generateCSR(key, config)
	if csrErr != nil {
		err = fmt.Errorf("generate ca failed, %v", csrErr)
		return
	}
	crt, err = generateCRT(key, csr, config.Expiration, true)
	if err != nil {
		err = fmt.Errorf("generate ca failed, %v", err)
		return
	}
	return
}
