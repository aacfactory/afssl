package afssl_test

import (
	"fmt"
	"github.com/aacfactory/afssl"
	"testing"
)

func TestNewAcme(t *testing.T) {
	//os.Setenv("ALICLOUD_ACCESS_KEY", "your aliyun access key")
	//os.Setenv("ALICLOUD_SECRET_KEY", "your aliyun sercet key")
	cacheManager, cacheManagerErr := afssl.NewFileAcmeCacheManager("G:/acme4")
	if cacheManagerErr != nil {
		t.Error(cacheManagerErr)
		return
	}
	acme, acmeErr := afssl.NewAcme("acme@foo.bar", "alidns", "*.foo.bar", afssl.CustomizeAcmeCacheManager(cacheManager))
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
	acme.Close()
}
