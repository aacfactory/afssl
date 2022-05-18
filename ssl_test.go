package afssl_test

import (
	"fmt"
	"github.com/aacfactory/afssl"
	"testing"
)

func TestGenerateSSL(t *testing.T) {
	config := afssl.Config{
		KeyBits:            1024,
		Country:            "CN",
		Province:           "Shanghai",
		City:               "Shanghai",
		Organization:       "AAC FACTORY",
		OrganizationalUnit: "AF",
		CommonName:         "AFSSL",
		IPs:                []string{"192.168.22.33"},
		DelegationEnabled:  true,
		Expiration:         afssl.ThreeMouths,
	}

	caPEM, caKeyPEM, serverPEM, serverKeyPEM, clientPEM, clientKeyPEM, err := afssl.GenerateSSL(config)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("ca---------------------------")
	fmt.Println(string(caPEM))
	fmt.Println(string(caKeyPEM))
	fmt.Println("server---------------------------")
	fmt.Println(string(serverPEM))
	fmt.Println(string(serverKeyPEM))
	fmt.Println("client---------------------------")
	fmt.Println(string(clientPEM))
	fmt.Println(string(clientKeyPEM))
}
