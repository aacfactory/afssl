package afssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"sync"
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
	RequestCertificateTimeout time.Duration
	Log                       AcmeLogger
}

func NewAcme(email string, dnsProvider string, domains []string, opts ...AcmeOption) (v Acme, err error) {
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
	if domains == nil || len(domains) == 0 {
		err = fmt.Errorf("afssl: new acme failed, domains is empty")
		return
	}
	for i, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			err = fmt.Errorf("afssl: new acme failed, one of domains is empty")
			return
		}
		domains[i] = domain
	}
	opt := &AcmeOptions{
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

	privateKey, privateKeyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if privateKeyErr != nil {
		err = fmt.Errorf("afssl: new acme failed, generate private key failed, %v", privateKeyErr)
		return
	}
	user := &acmeUser{
		Email: email,
		key:   privateKey,
	}
	config := lego.NewConfig(user)
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
	acmeRegistration, registerErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if registerErr != nil {
		err = fmt.Errorf("afssl: new acme failed, acme client register failed, %v", registerErr)
		return
	}
	user.Registration = acmeRegistration
	v = &acme{
		client:  client,
		domains: domains,
		once:    sync.Once{},
		stopCh:  make(chan struct{}, 1),
	}
	return
}

type acme struct {
	log          AcmeLogger
	client       *lego.Client
	domains      []string
	once         sync.Once
	config       *tls.Config
	certificates *certificate.Resource
	certPEM      []byte
	renewAT      time.Time
	err          error
	stopCh       chan struct{}
}

func (a *acme) Obtain() (config *tls.Config, err error) {
	a.once.Do(func() {
		request := certificate.ObtainRequest{
			Domains: a.domains,
			Bundle:  true,
		}
		certificates, obtainErr := a.client.Certificate.Obtain(request)
		if obtainErr != nil {
			a.err = fmt.Errorf("afssl: obtain failed, %v", obtainErr)
			return
		}
		handleErr := a.handle(certificates)
		if handleErr != nil {
			a.err = fmt.Errorf("afssl: obtain failed, %v", handleErr)
			return
		}
	})
	config = a.config
	err = a.err
	return
}

func (a *acme) Close() {
	a.stopCh <- struct{}{}
	close(a.stopCh)
}

func (a *acme) handle(certificates *certificate.Resource) (err error) {
	resp, getErr := http.Get(certificates.CertStableURL)
	if getErr != nil {
		a.err = fmt.Errorf("afssl: handle certificates failed, get cert from %s failed, %v", certificates.CertStableURL, getErr)
		return
	}
	certPEM, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		a.err = fmt.Errorf("afssl: handle certificates failed, read cert from response body failed, %v", readErr)
		return
	}
	certBlock, _ := pem.Decode(certPEM)
	cert0, parseCertificateErr := x509.ParseCertificate(certBlock.Bytes)
	if parseCertificateErr != nil {
		a.err = fmt.Errorf("afssl: handle certificates failed, parse cert pem failed, %v", parseCertificateErr)
		return
	}
	renewAT := cert0.NotAfter.Local()
	cert, certErr := tls.X509KeyPair(certPEM, certificates.PrivateKey)
	if certErr != nil {
		a.err = fmt.Errorf("afssl: handle certificates failed, make x509 key pair failed, %v", certErr)
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
