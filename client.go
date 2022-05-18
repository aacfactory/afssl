package afssl

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

func generateClient(config Config) (crt *x509.Certificate, key *rsa.PrivateKey, err error) {
	key, err = generateKEY(config.KeyBits)
	if err != nil {
		err = fmt.Errorf("generate client failed, %v", err)
		return
	}
	csr, csrErr := generateCSR(key, config)
	if csrErr != nil {
		err = fmt.Errorf("generate client failed, %v", csrErr)
		return
	}
	crt, err = generateCRT(key, csr, config.Expiration, false)
	if err != nil {
		err = fmt.Errorf("generate client failed, %v", err)
		return
	}
	return
}
