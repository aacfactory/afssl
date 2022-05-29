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

func AcmeCertificateCacheDIR(v string) AcmeOption {
	return func(options *AcmeOptions) error {
		v = strings.TrimSpace(v)
		options.CacheDIR = v
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

type AcmeOptions struct {
	CacheDIR                  string
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
		CacheDIR:                  "",
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
	cachedDIR := strings.TrimSpace(opt.CacheDIR)
	if cachedDIR == "" {
		cachedDIR = ".afssl"
	}
	if !pathExist(cachedDIR) {
		mkErr := os.MkdirAll(cachedDIR, 0600)
		if mkErr != nil {
			err = fmt.Errorf("afssl: make acme certificates cached dir(%s) failed, %v", cachedDIR, mkErr)
			return
		}
	}
	user := &acmeUser{
		Email: email,
		//key:   privateKey,
	}
	// cached registration
	cachedRegistrationPath := filepath.Join(cachedDIR, fmt.Sprintf("%s.registration.json", email))
	if pathExist(cachedRegistrationPath) {
		acmeRegistrationBytes, readErr := ioutil.ReadFile(cachedRegistrationPath)
		if readErr != nil {
			err = fmt.Errorf("afssl: new acme failed, read cached registration failed, %v", readErr)
			return
		}
		acmeRegistration := &registration.Resource{}
		decodeErr := json.Unmarshal(acmeRegistrationBytes, acmeRegistration)
		if decodeErr != nil {
			err = fmt.Errorf("afssl: new acme failed, decode cached registration failed, %v", decodeErr)
			return
		}
		user.Registration = acmeRegistration
		// key
		keyPath := filepath.Join(cachedDIR, fmt.Sprintf("%s.key", email))
		userKeyPEM, readKeyErr := ioutil.ReadFile(keyPath)
		if readKeyErr != nil {
			err = fmt.Errorf("afssl: new acme failed, read cached user key failed, %v", readKeyErr)
			return
		}
		keyBlock, _ := pem.Decode(userKeyPEM)
		key, keyErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if keyErr != nil {
			err = fmt.Errorf("afssl: new acme failed, parse cached user key failed, %v", keyErr)
			return
		}
		user.key = key
	}
	if user.key == nil {
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
		newRegistration, registerErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if registerErr != nil {
			err = fmt.Errorf("afssl: new acme failed, acme client register failed, %v", registerErr)
			return
		}
		user.Registration = newRegistration
		acmeRegistrationBytes, encodeErr := json.Marshal(newRegistration)
		if encodeErr != nil {
			err = fmt.Errorf("afssl: new acme failed, encode acme user registration failed, %v", encodeErr)
			return
		}
		writeRegErr := ioutil.WriteFile(cachedRegistrationPath, acmeRegistrationBytes, 0600)
		if writeRegErr != nil {
			err = fmt.Errorf("afssl: new acme failed, save acme cached user registration  failed, %v", writeRegErr)
			return
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(user.key.(*rsa.PrivateKey)),
		})
		writeKeyErr := ioutil.WriteFile(filepath.Join(cachedDIR, fmt.Sprintf("%s.key", email)), keyPEM, 0600)
		if writeKeyErr != nil {
			err = fmt.Errorf("afssl: new acme failed, save acme cached user key  failed, %v", writeKeyErr)
			return
		}
	}
	v = &acme{
		client:   client,
		domain:   domain,
		cacheDIR: cachedDIR,
		stopCh:   make(chan struct{}, 1),
	}
	return
}

type acme struct {
	log          AcmeLogger
	client       *lego.Client
	domain       string
	cacheDIR     string
	config       *tls.Config
	certificates *certificate.Resource
	renewAT      time.Time
	stopCh       chan struct{}
}

func (a *acme) Obtain() (config *tls.Config, err error) {
	ok, cacheErr := a.getCached()
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

func (a *acme) makeupDomainForCached() (v string) {
	if strings.Contains(a.domain, "*") {
		v = strings.ReplaceAll(a.domain, "*", "[x]")
		return
	}
	v = a.domain
	return
}

func (a *acme) getCached() (ok bool, err error) {
	cachedDomain := a.makeupDomainForCached()
	// res
	resPath := filepath.Join(a.cacheDIR, fmt.Sprintf("%s.json", cachedDomain))
	if !pathExist(resPath) {
		return
	}
	resBytes, readResErr := ioutil.ReadFile(resPath)
	if readResErr != nil {
		err = fmt.Errorf("afssl: read certificates resouce file from cached file(%s) failed, %v", resPath, readResErr)
		return
	}
	certificates := &certificate.Resource{}
	decodeResErr := json.Unmarshal(resBytes, certificates)
	if decodeResErr != nil {
		err = fmt.Errorf("afssl: decode read certificates resouce content from cached file(%s) failed, %v", resPath, decodeResErr)
		return
	}
	// key
	keyPath := filepath.Join(a.cacheDIR, fmt.Sprintf("%s.key", cachedDomain))
	if !pathExist(keyPath) {
		return
	}
	keyPEM, readKeyErr := ioutil.ReadFile(keyPath)
	if readKeyErr != nil {
		err = fmt.Errorf("afssl: read key pem file from cached file(%s) failed, %v", keyPath, readKeyErr)
		return
	}
	// cert
	certPath := filepath.Join(a.cacheDIR, fmt.Sprintf("%s.crt", cachedDomain))
	if !pathExist(certPath) {
		return
	}
	certPEM, readCertErr := ioutil.ReadFile(certPath)
	if readCertErr != nil {
		err = fmt.Errorf("afssl: read cert pem file from cached file(%s) failed, %v", certPath, readCertErr)
		return
	}
	certBlock, _ := pem.Decode(certPEM)
	cert0, parseCertificateErr := x509.ParseCertificate(certBlock.Bytes)
	if parseCertificateErr != nil {
		err = fmt.Errorf("afssl: parse cached cert pem failed, %v", parseCertificateErr)
		return
	}
	notAfter := cert0.NotAfter.Local()
	if time.Now().After(notAfter) {
		_ = os.Remove(resPath)
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		return
	}
	cert, certErr := tls.X509KeyPair(certPEM, keyPEM)
	if certErr != nil {
		_ = os.Remove(resPath)
		_ = os.Remove(certPath)
		_ = os.Remove(keyPath)
		return
	}
	a.config = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	a.certificates = certificates
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
	a.config = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	a.certificates = certificates
	a.renewAT = renewAT
	// make cache
	cachedDomain := a.makeupDomainForCached()
	resBytes, encodeResErr := json.Marshal(a.certificates)
	if encodeResErr != nil {
		err = fmt.Errorf("afssl: encode acme certificates failed, %v", encodeResErr)
		return
	}
	resPath := filepath.Join(a.cacheDIR, fmt.Sprintf("%s.json", cachedDomain))
	writeResErr := ioutil.WriteFile(resPath, resBytes, 0600)
	if writeResErr != nil {
		err = fmt.Errorf("afssl: write acme certificates cache failed, %v", writeResErr)
		return
	}
	certPath := filepath.Join(a.cacheDIR, fmt.Sprintf("%s.crt", cachedDomain))
	writeCertErr := ioutil.WriteFile(certPath, certPEM, 0600)
	if writeCertErr != nil {
		err = fmt.Errorf("afssl: write acme cert pem cache failed, %v", writeCertErr)
		return
	}
	keyPath := filepath.Join(a.cacheDIR, fmt.Sprintf("%s.key", cachedDomain))
	writeKeyErr := ioutil.WriteFile(keyPath, keyPEM, 0600)
	if writeKeyErr != nil {
		err = fmt.Errorf("afssl: write acme key pem cache failed, %v", writeKeyErr)
		return
	}
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
