package tlcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"io"
	"net"
	"sync"
	"time"
)

const (
	VersionTLCP = 0x0101
)

const (
	maxPlaintext      = 16384
	maxCiphertext     = 16384 + 2048
	recordHeaderLen   = 5
	maxHandshake      = 65536
	maxUselessRecords = 16
)

type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

const (
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
)

func HandshakeMessageTypeName(id uint8) string {
	switch id {
	case typeClientHello:
		return "Client Hello"
	case typeServerHello:
		return "Server Hello"
	case typeCertificate:
		return "Certificate"
	case typeServerKeyExchange:
		return "Server Key Exchange"
	case typeCertificateRequest:
		return "Certificate Request"
	case typeServerHelloDone:
		return "Server Hello Done"
	case typeCertificateVerify:
		return "Certificate Verify"
	case typeClientKeyExchange:
		return "Client Key Exchange"
	case typeFinished:
		return "Finished"
	}
	return fmt.Sprintf("0x%02X", id)
}

const (
	compressionNone uint8 = 0
)

type CurveID uint16

const (
	CurveSM2 CurveID = 41
)

const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
	certTypeIbcParams = 80
)

type ConnectionState struct {
	Version           uint16
	HandshakeComplete bool
	DidResume         bool
	CipherSuite       uint16
	ServerName        string
	PeerCertificates  []*smx509.Certificate
	VerifiedChains    [][]*smx509.Certificate
}

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
	RequireAndVerifyAnyKeyUsageClientCert
)

func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert, RequireAndVerifyAnyKeyUsageClientCert:
		return true
	default:
		return false
	}
}

type ClientHelloInfo struct {
	CipherSuites      []uint16
	ServerName        string
	SupportedVersions []uint16
	Conn              net.Conn
	config            *Config
	ctx               context.Context
}

func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

type CertificateRequestInfo struct {
	AcceptableCAs [][]byte
	Version       uint16
	ctx           context.Context
}

func (cri *CertificateRequestInfo) Context() context.Context {
	return cri.ctx
}

func (cri *CertificateRequestInfo) SupportsCertificate(c *Certificate) error {
	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = smx509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}
	return errors.New("chain is not signed by an acceptable CA")
}

var supportedVersions = []uint16{
	VersionTLCP,
}

const (
	roleClient = true
	roleServer = false
)

var errNoCertificates = errors.New("tlcp: no certificates configured")

type Config struct {
	Rand                        io.Reader
	Time                        func() time.Time
	Certificates                []Certificate
	GetCertificate              func(*ClientHelloInfo) (*Certificate, error)
	GetKECertificate            func(*ClientHelloInfo) (*Certificate, error)
	GetClientCertificate        func(*CertificateRequestInfo) (*Certificate, error)
	GetClientKECertificate      func(*CertificateRequestInfo) (*Certificate, error)
	GetConfigForClient          func(*ClientHelloInfo) (*Config, error)
	VerifyPeerCertificate       func(rawCerts [][]byte, verifiedChains [][]*smx509.Certificate) error
	VerifyConnection            func(ConnectionState) error
	RootCAs                     *smx509.CertPool
	ServerName                  string
	ClientAuth                  ClientAuthType
	ClientCAs                   *smx509.CertPool
	InsecureSkipVerify          bool
	CipherSuites                []uint16
	SessionCache                SessionCache
	MinVersion                  uint16
	MaxVersion                  uint16
	DynamicRecordSizingDisabled bool
	OnAlert                     func(code uint8, conn *Conn)
	mutex                       sync.RWMutex
	ClientECDHEParamsAsVector   bool
}

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return &Config{
		Rand:                        c.Rand,
		Time:                        c.Time,
		Certificates:                c.Certificates,
		GetCertificate:              c.GetCertificate,
		GetKECertificate:            c.GetKECertificate,
		GetClientCertificate:        c.GetClientCertificate,
		GetClientKECertificate:      c.GetClientKECertificate,
		GetConfigForClient:          c.GetConfigForClient,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
		VerifyConnection:            c.VerifyConnection,
		RootCAs:                     c.RootCAs,
		ServerName:                  c.ServerName,
		ClientECDHEParamsAsVector:   c.ClientECDHEParamsAsVector,
		ClientAuth:                  c.ClientAuth,
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		SessionCache:                c.SessionCache,
		MinVersion:                  c.MinVersion,
		MaxVersion:                  c.MaxVersion,
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		OnAlert:                     c.OnAlert,
	}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}
	return defaultCipherSuites
}

func (c *Config) supportedVersions(isClient bool) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) maxSupportedVersion(isClient bool) uint16 {
	supportedVersions := c.supportedVersions(isClient)
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

func (c *Config) mutualVersion(isClient bool, peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions(isClient)
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				return v, true
			}
		}
	}
	return 0, false
}

func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetCertificate != nil &&
		(len(c.Certificates) == 0 || len(clientHello.ServerName) > 0) {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		return nil, errNoCertificates
	}
	return &c.Certificates[0], nil
}

func (c *Config) getEKCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	if c.GetKECertificate != nil && (len(c.Certificates) < 2) {
		cert, err := c.GetKECertificate(clientHello)
		if cert != nil || err != nil {
			return cert, err
		}
	}
	if len(c.Certificates) < 2 {
		return nil, errNoCertificates
	}
	return &c.Certificates[1], nil
}

func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	if (maxVersion & 0xFF00) == 0x0300 {
		return versions
	}
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

type Certificate struct {
	Certificate [][]byte
	PrivateKey  crypto.PrivateKey
	Leaf        *smx509.Certificate
}

func (c *Certificate) leaf() (*smx509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return smx509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
	messageType() uint8
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

func unexpectedMessageError(wanted, got interface{}) error {
	return fmt.Errorf("tlcp: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

type CertificateVerificationError struct {
	UnverifiedCertificates []*smx509.Certificate
	Err                    error
}

func (e *CertificateVerificationError) Error() string {
	return fmt.Sprintf("tlcp: failed to verify certificate: %s", e.Err)
}

func (e *CertificateVerificationError) Unwrap() error {
	return e.Err
}
