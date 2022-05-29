package afssl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"io"
	"io/ioutil"
	slog "log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Acme interface {
	Obtain() (config *tls.Config, err error)
	Close()
}

type AcmeLogger interface {
	Fatal(args ...interface{})
	Fatalln(args ...interface{})
	Fatalf(format string, args ...interface{})
	Print(args ...interface{})
	Println(args ...interface{})
	Printf(format string, args ...interface{})
}

type AcmeOption func(*AcmeOptions) error

func CustomizeAcmeCacheManager(v AcmeCacheManager) AcmeOption {
	return func(options *AcmeOptions) error {
		if v == nil {
			return fmt.Errorf("acme cache manager is nil")
		}
		options.CacheManager = v
		return nil
	}
}

func AcmeRequestCertificateTimeout(v time.Duration) AcmeOption {
	return func(options *AcmeOptions) error {
		if v < 2*time.Second {
			v = 30 * time.Second
		}
		options.RequestCertificateTimeout = v
		return nil
	}
}

func CustomizeAcmeLogger(v AcmeLogger) AcmeOption {
	return func(options *AcmeOptions) error {
		if v == nil {
			return nil
		}
		options.Log = v
		return nil
	}
}

type AcmeCacheManager interface {
	StoreUser(email string, keyPEM []byte, resource *registration.Resource) (err error)
	LoadUser(email string) (has bool, keyPEM []byte, resource *registration.Resource, err error)
	StoreCertificate(domain string, certPEM []byte, keyPEM []byte, resource *certificate.Resource) (err error)
	LoadCertificate(domain string) (has bool, certPEM []byte, keyPEM []byte, resource *certificate.Resource, err error)
}

func NewFileAcmeCacheManager(cacheDIR string) (cm AcmeCacheManager, err error) {
	cacheDIR = strings.TrimSpace(cacheDIR)
	if cacheDIR == "" {
		err = fmt.Errorf("afssl: new file acme cache manager failed, cache dir is empty")
		return
	}
	if !pathExist(cacheDIR) {
		mkdirErr := os.MkdirAll(cacheDIR, 0600)
		if mkdirErr != nil {
			err = fmt.Errorf("afssl: new file acme cache manager failed, make cache dir failed, %v", mkdirErr)
			return
		}
	}
	cm = &fileAcmeCacheManager{
		dir: cacheDIR,
	}
	return
}

type fileAcmeCacheManager struct {
	dir string
}

func (manager *fileAcmeCacheManager) StoreUser(email string, keyPEM []byte, resource *registration.Resource) (err error) {
	resourceContent, encodeResourceErr := json.Marshal(resource)
	if encodeResourceErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store user failed, %v", encodeResourceErr)
		return
	}
	userKeyPath := filepath.Join(manager.dir, fmt.Sprintf("%s.key", email))
	saveKeyErr := ioutil.WriteFile(userKeyPath, keyPEM, 0600)
	if saveKeyErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store user failed, %v", saveKeyErr)
		return
	}
	userResourcePath := filepath.Join(manager.dir, fmt.Sprintf("%s.json", email))
	saveResourceErr := ioutil.WriteFile(userResourcePath, resourceContent, 0600)
	if saveResourceErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store user failed, %v", saveResourceErr)
		return
	}
	return
}

func (manager *fileAcmeCacheManager) LoadUser(email string) (has bool, keyPEM []byte, resource *registration.Resource, err error) {
	userKeyPath := filepath.Join(manager.dir, fmt.Sprintf("%s.key", email))
	if !pathExist(userKeyPath) {
		return
	}
	keyPEM, err = ioutil.ReadFile(filepath.Join(manager.dir, fmt.Sprintf("%s.key", email)))
	if err != nil {
		err = fmt.Errorf("afssl: acme file cache manager load user failed, %v", err)
		return
	}
	resourceContent, readResourceErr := ioutil.ReadFile(filepath.Join(manager.dir, fmt.Sprintf("%s.json", email)))
	if readResourceErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager load user failed, %v", readResourceErr)
		return
	}
	resource = &registration.Resource{}
	decodeErr := json.Unmarshal(resourceContent, resource)
	if decodeErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager load user failed, %v", decodeErr)
		return
	}
	has = true
	return
}

func (manager *fileAcmeCacheManager) StoreCertificate(domain string, certPEM []byte, keyPEM []byte, resource *certificate.Resource) (err error) {
	if strings.Contains(domain, "*") {
		domain = strings.ReplaceAll(domain, "*", "[x]")
	}
	resourceContent, encodeResourceErr := json.Marshal(resource)
	if encodeResourceErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store certificate failed, %v", encodeResourceErr)
		return
	}
	certPath := filepath.Join(manager.dir, fmt.Sprintf("%s.crt", domain))
	saveCertErr := ioutil.WriteFile(certPath, certPEM, 0600)
	if saveCertErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store certificate failed, %v", saveCertErr)
		return
	}
	keyPath := filepath.Join(manager.dir, fmt.Sprintf("%s.key", domain))
	saveKeyErr := ioutil.WriteFile(keyPath, keyPEM, 0600)
	if saveKeyErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store certificate failed, %v", saveKeyErr)
		return
	}
	resourcePath := filepath.Join(manager.dir, fmt.Sprintf("%s.json", domain))
	saveResourceErr := ioutil.WriteFile(resourcePath, resourceContent, 0600)
	if saveResourceErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager store certificate failed, %v", saveResourceErr)
		return
	}
	return
}

func (manager *fileAcmeCacheManager) LoadCertificate(domain string) (has bool, certPEM []byte, keyPEM []byte, resource *certificate.Resource, err error) {
	if strings.Contains(domain, "*") {
		domain = strings.ReplaceAll(domain, "*", "[x]")
	}
	certPath := filepath.Join(manager.dir, fmt.Sprintf("%s.crt", domain))
	if !pathExist(certPath) {
		return
	}
	certPEM, err = ioutil.ReadFile(certPath)
	if err != nil {
		err = fmt.Errorf("afssl: acme file cache manager load certificate failed, %v", err)
		return
	}
	keyPath := filepath.Join(manager.dir, fmt.Sprintf("%s.key", domain))
	keyPEM, err = ioutil.ReadFile(keyPath)
	if err != nil {
		err = fmt.Errorf("afssl: acme file cache manager load certificate failed, %v", err)
		return
	}
	resourcePath := filepath.Join(manager.dir, fmt.Sprintf("%s.json", domain))
	resourceContent, resourceErr := ioutil.ReadFile(resourcePath)
	if resourceErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager load certificate failed, %v", resourceErr)
		return
	}
	resource = &certificate.Resource{}
	decodeErr := json.Unmarshal(resourceContent, resource)
	if decodeErr != nil {
		err = fmt.Errorf("afssl: acme file cache manager load certificate failed, %v", decodeErr)
		return
	}
	has = true
	return
}

type AcmeOptions struct {
	CacheManager              AcmeCacheManager
	RequestCertificateTimeout time.Duration
	Log                       AcmeLogger
}

func NewAcme(email string, dnsProvider string, domain string, opts ...AcmeOption) (v Acme, err error) {
	email = strings.TrimSpace(email)
	if email == "" || strings.Index(email, "@") < 1 {
		err = fmt.Errorf("afssl: new acme failed, email is invalid")
		return
	}
	dnsProvider = strings.TrimSpace(dnsProvider)
	if dnsProvider == "" {
		err = fmt.Errorf("afssl: new acme failed, dns provider is empty")
		return
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		err = fmt.Errorf("afssl: new acme failed, one of domains is empty")
		return
	}
	opt := &AcmeOptions{
		CacheManager:              nil,
		RequestCertificateTimeout: 30 * time.Second,
		Log:                       nil,
	}
	if opts != nil {
		for _, option := range opts {
			optErr := option(opt)
			if optErr != nil {
				err = fmt.Errorf("afssl: new acme failed, %v", optErr)
				return
			}
		}
	}
	if opt.Log == nil {
		var out io.Writer
		devNull, openDevNullErr := os.Open(os.DevNull)
		if openDevNullErr != nil {
			out = ioutil.Discard
		} else {
			out = devNull
		}
		opt.Log = slog.New(out, "", slog.LstdFlags)
	}
	log.Logger = opt.Log
	if opt.CacheManager == nil {
		defaultCacheDIR := "~/.afssl"
		if runtime.GOOS == "windows" {
			defaultCacheDIR = "./.afssl"
		}
		defaultCacheManager, cmErr := NewFileAcmeCacheManager(defaultCacheDIR)
		if cmErr != nil {
			err = fmt.Errorf("afssl: new acme failed, %v", cmErr)
			return
		}
		opt.CacheManager = defaultCacheManager
	}

	user := &acmeUser{
		Email: email,
	}
	hasUser, userKeyPEM, userResource, loadUserErr := opt.CacheManager.LoadUser(email)
	if loadUserErr != nil {
		err = fmt.Errorf("afssl: new acme failed, %v", loadUserErr)
		return
	}
	if hasUser {
		user.Registration = userResource
		keyBlock, _ := pem.Decode(userKeyPEM)
		key, keyErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if keyErr != nil {
			err = fmt.Errorf("afssl: new acme failed, parse cached user key failed, %v", keyErr)
			return
		}
		user.key = key
	} else {
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			err = fmt.Errorf("afssl: new acme failed, create user private key failed, %v", keyErr)
			return
		}
		user.key = key
	}
	config := lego.NewConfig(user)
	config.Certificate.Timeout = opt.RequestCertificateTimeout
	client, clientErr := lego.NewClient(config)
	if clientErr != nil {
		err = fmt.Errorf("afssl: new acme failed, new acme client failed, %v", clientErr)
		return
	}
	provider, providerErr := dns.NewDNSChallengeProviderByName(dnsProvider)
	if providerErr != nil {
		err = fmt.Errorf("afssl: new acme failed, new acme dns chanllenge provider failed, %v", providerErr)
		return
	}
	setProviderErr := client.Challenge.SetDNS01Provider(provider)
	if setProviderErr != nil {
		err = fmt.Errorf("afssl: new acme failed, acme client set dns chanllenge provider failed, %v", setProviderErr)
		return
	}
	if user.Registration == nil {
		userRegistration, registerErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if registerErr != nil {
			err = fmt.Errorf("afssl: new acme failed, acme client register failed, %v", registerErr)
			return
		}
		user.Registration = userRegistration
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(user.key.(*rsa.PrivateKey)),
		})
		storeUserErr := opt.CacheManager.StoreUser(email, keyPEM, user.Registration)
		if storeUserErr != nil {
			err = fmt.Errorf("afssl: new acme failed, store acme user failed, %v", storeUserErr)
			return
		}
	}
	v = &acme{
		client:       client,
		cacheManager: opt.CacheManager,
		domain:       domain,
		stopCh:       make(chan struct{}, 1),
	}
	return
}

type acme struct {
	log          AcmeLogger
	cacheManager AcmeCacheManager
	client       *lego.Client
	domain       string
	config       *tls.Config
	certificates *certificate.Resource
	renewAT      time.Time
	stopCh       chan struct{}
}

func (a *acme) Obtain() (config *tls.Config, err error) {
	ok, cacheErr := a.getCertificateFromCache()
	if cacheErr != nil {
		err = cacheErr
		return
	}
	if ok {
		config = a.config
		go a.renew()
		return
	}
	request := certificate.ObtainRequest{
		Domains: []string{a.domain},
		Bundle:  true,
	}
	certificates, obtainErr := a.client.Certificate.Obtain(request)
	if obtainErr != nil {
		err = fmt.Errorf("afssl: obtain failed, %v", obtainErr)
		return
	}
	handleErr := a.handle(certificates)
	if handleErr != nil {
		err = fmt.Errorf("afssl: obtain failed, %v", handleErr)
		return
	}
	config = a.config
	return
}

func (a *acme) Close() {
	a.stopCh <- struct{}{}
	close(a.stopCh)
}

func (a *acme) getCertificateFromCache() (ok bool, err error) {
	has, certPEM, keyPEM, resource, loadErr := a.cacheManager.LoadCertificate(a.domain)
	if loadErr != nil {
		err = fmt.Errorf("afssl: get certificate from cache failed, %v", loadErr)
		return
	}
	if !has {
		return
	}
	// cert
	certBlock, _ := pem.Decode(certPEM)
	cert0, parseCertificateErr := x509.ParseCertificate(certBlock.Bytes)
	if parseCertificateErr != nil {
		err = fmt.Errorf("afssl: parse cached cert pem failed, %v", parseCertificateErr)
		return
	}
	notAfter := cert0.NotAfter.Local()
	if time.Now().After(notAfter) {
		return
	}
	cert, certErr := tls.X509KeyPair(certPEM, keyPEM)
	if certErr != nil {
		return
	}
	a.config = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	a.certificates = resource
	a.renewAT = notAfter
	ok = true
	return
}

func (a *acme) handle(certificates *certificate.Resource) (err error) {
	resp, getErr := http.Get(certificates.CertStableURL)
	if getErr != nil {
		err = fmt.Errorf("afssl: handle certificates failed, get cert from %s failed, %v", certificates.CertStableURL, getErr)
		return
	}
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		err = fmt.Errorf("afssl: handle certificates failed, get cert from %s failed, %v", certificates.CertStableURL, string(body))
		return
	}
	certPEM, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		err = fmt.Errorf("afssl: handle certificates failed, read cert from response body failed, %v", readErr)
		return
	}
	certBlock, _ := pem.Decode(certPEM)
	cert0, parseCertificateErr := x509.ParseCertificate(certBlock.Bytes)
	if parseCertificateErr != nil {
		err = fmt.Errorf("afssl: handle certificates failed, parse cert pem failed, %v", parseCertificateErr)
		return
	}
	renewAT := cert0.NotAfter.Local()
	keyPEM := certificates.PrivateKey
	cert, certErr := tls.X509KeyPair(certPEM, keyPEM)
	if certErr != nil {
		err = fmt.Errorf("afssl: handle certificates failed, make x509 key pair failed, %v", certErr)
		return
	}
	storeErr := a.cacheManager.StoreCertificate(a.domain, certPEM, keyPEM, certificates)
	if storeErr != nil {
		err = fmt.Errorf("afssl: handle certificates failed, cache certificate failed, %v", storeErr)
		return
	}

	a.config = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	a.certificates = certificates
	a.renewAT = renewAT

	go a.renew()
	return
}

func (a *acme) renew() {
	select {
	case <-a.stopCh:
		return
	case <-time.After(a.renewAT.Sub(time.Now())):
		break
	}
	certificates, renewErr := a.client.Certificate.Renew(*a.certificates, true, true, "")
	if renewErr != nil {
		if a.log != nil {
			a.log.Println(fmt.Sprintf("afssl: renew failed, %v", renewErr))
		}
		a.renewAT = time.Now().Add(1 * time.Minute)
		a.renew()
		return
	}
	handleErr := a.handle(certificates)
	if handleErr != nil {
		if a.log != nil {
			a.log.Println(fmt.Sprintf("afssl: handle renew result failed, %v", handleErr))
		}
		a.renewAT = time.Now().Add(1 * time.Minute)
		a.renew()
		return
	}
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}

func (u acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
