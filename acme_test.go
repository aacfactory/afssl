package afssl_test

import (
	"fmt"
	"github.com/aacfactory/afssl"
	"os"
	"testing"
)

func TestNewAcme(t *testing.T) {
	os.Setenv("ALICLOUD_ACCESS_KEY", "your aliyun access key")
	os.Setenv("ALICLOUD_SECRET_KEY", "your aliyun sercet key")
	acme, acmeErr := afssl.NewAcme("foo@bar.com", "alidns", []string{"*.foo.bar"})
	if acmeErr != nil {
		t.Error(acmeErr)
		return
	}
	config, obtainErr := acme.Obtain()
	if obtainErr != nil {
		t.Error(obtainErr)
		return
	}
	fmt.Println(fmt.Sprintf("%+v", config))
}
