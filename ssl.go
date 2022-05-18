package afssl

import (
	"fmt"
	"strings"
	"time"
)

const (
	OneMouth    = 730 * time.Hour
	ThreeMouths = 3 * OneMouth
	OneYear     = 12 * OneMouth
	TenYears    = 10 * OneYear
)

type Config struct {
	KeyBits            int
	Country            string
	Province           string
	City               string
	Organization       string
	OrganizationalUnit string
	CommonName         string
	IPs                []string
	DelegationEnabled  bool
	Expiration         time.Duration
}

func (config Config) Validate() (err error) {
	// key
	if config.KeyBits < 1 {
		err = fmt.Errorf("invalid config")
		return
	}
	// subject
	empty := func(s string) bool { return strings.TrimSpace(s) == "" }
	if empty(config.CommonName) || empty(config.Country) || empty(config.Province) || empty(config.Organization) || empty(config.OrganizationalUnit) {
		err = fmt.Errorf("invalid config")
		return
	}
	// exp
	if config.Expiration < 24*time.Hour {
		err = fmt.Errorf("invalid config")
		return
	}
	return
}

func GenerateSSL(config Config) (caPEM []byte, caKeyPEM []byte, serverPEM []byte, serverKeyPEM []byte, clientPEM []byte, clientKeyPEM []byte, err error) {
	err = config.Validate()
	if err != nil {
		err = fmt.Errorf("generate ssl failed, %v", err)
		return
	}
	// ca
	caCRT, caKEY, caErr := generateCA(config)
	if caErr != nil {
		err = fmt.Errorf("generate ssl failed, %v", caErr)
		return
	}
	caPEM, err = encodeCRT(caKEY, caCRT, caCRT)
	if err != nil {
		err = fmt.Errorf("generate ssl failed, encode ca failed, %v", err)
		return
	}
	caKeyPEM, _ = encodeKEY(caKEY)
	// server
	serverCRT, serverKEY, serverErr := generateServer(config)
	if serverErr != nil {
		err = fmt.Errorf("generate ssl failed, %v", serverErr)
		return
	}
	serverPEM, err = encodeCRT(serverKEY, caCRT, serverCRT)
	if err != nil {
		err = fmt.Errorf("generate ssl failed, encode server failed, %v", err)
		return
	}
	serverKeyPEM, _ = encodeKEY(serverKEY)
	// client
	clientCRT, clientKEY, clientErr := generateServer(config)
	if clientErr != nil {
		err = fmt.Errorf("generate ssl failed, %v", clientErr)
		return
	}
	clientPEM, err = encodeCRT(clientKEY, caCRT, clientCRT)
	if err != nil {
		err = fmt.Errorf("generate ssl failed, encode client failed, %v", err)
		return
	}
	clientKeyPEM, _ = encodeKEY(clientKEY)
	return
}
