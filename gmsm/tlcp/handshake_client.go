package tlcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"hash"
	"sync/atomic"
	"time"
)

type clientHandshakeState struct {
	c                *Conn
	ctx              context.Context
	serverHello      *serverHelloMsg
	hello            *clientHelloMsg
	suite            *cipherSuite
	finishedHash     finishedHash
	masterSecret     []byte
	session          *SessionState
	authCert         *Certificate
	encCert          *Certificate
	peerCertificates []*smx509.Certificate
}

func (c *Conn) makeClientHello() (*clientHelloMsg, error) {
	config := c.config
	supportVers := config.supportedVersions(roleClient)
	if len(supportVers) == 0 {
		return nil, errors.New("tlcp: no supported versions satisfy MinVersion and MaxVersion")
	}
	clientHelloVersion := config.maxSupportedVersion(roleClient)
	hello := &clientHelloMsg{
		vers:               clientHelloVersion,
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
	}
	hasAuthKeyPair := false
	if len(config.Certificates) > 0 || config.GetClientCertificate != nil {
		hasAuthKeyPair = true
	}
	hasEncKeyPair := false
	if len(config.Certificates) > 1 || config.GetClientKECertificate != nil {
		hasEncKeyPair = true
	}
	preferenceOrder := cipherSuitesPreferenceOrder
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))
	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		if (suiteId == ECDHE_SM4_GCM_SM3 || suiteId == ECDHE_SM4_CBC_SM3) && !(hasAuthKeyPair && hasEncKeyPair) {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}
	var err error
	hello.random, err = c.tlcpRand()
	if err != nil {
		return nil, errors.New("tlcp: short read from Rand: " + err.Error())
	}
	return hello, nil
}

func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	if c.config == nil {
		c.config = defaultConfig()
	}
	c.didResume = false
	hello, err := c.makeClientHello()
	if err != nil {
		return err
	}
	c.serverName = c.config.ServerName

	dst := c.conn.RemoteAddr().String()
	sessionId, session := c.loadSession(dst, hello)
	defer func() {
		if session != nil && err != nil {
			c.config.SessionCache.Put(dst, nil)
			c.config.SessionCache.Put(sessionId, nil)
		}
	}()

	if _, err = c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err = c.pickProtocolVersion(serverHello); err != nil {
		return err
	}

	hs := &clientHandshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}

	if err = hs.handshake(); err != nil {
		return err
	}

	return nil
}

func (c *Conn) loadSession(dest string, hello *clientHelloMsg) (cacheKey string, session *SessionState) {
	if c.config.SessionCache == nil {
		return
	}
	var ok = false

	session, ok = c.config.SessionCache.Get(dest)
	if !ok || session == nil {
		return cacheKey, nil
	}
	hello.sessionId = session.sessionId
	cacheKey = hex.EncodeToString(session.sessionId)

	return cacheKey, session
}

func (c *Conn) pickProtocolVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tlcp: server selected unsupported protocol version %x", peerVersion)
	}
	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

func (hs *clientHandshakeState) handshake() error {
	c := hs.c
	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}
	if err = transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err = transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}
	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if c.config.VerifyConnection != nil {
			if err = c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				_ = c.sendAlert(alertBadCertificate)
				return err
			}
		}
		if err = hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}
	} else {
		if err = hs.doFullHandshake(); err != nil {
			return err
		}
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}
		if err = hs.createNewSession(); err != nil {
			return err
		}
		if err = hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}
	atomic.StoreUint32(&c.handshakeStatus, 1)
	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		_ = hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: server chose an unconfigured cipher suite")
	}
	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c
	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	msg, err = c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	if c.handshakes == 0 {
		if err = c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: server's identity changed during renegotiation")
		}
	}
	hs.peerCertificates = c.peerCertificates
	keyAgreement := hs.suite.ka(c.vers)
	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		err = keyAgreement.processServerKeyExchange(hs, skx)
		if err != nil {
			_ = c.sendAlert(alertUnexpectedMessage)
			return err
		}
		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}
	var clientAuthCert *Certificate
	var clientEncCert *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true
		cri := &CertificateRequestInfo{AcceptableCAs: certReq.certificateAuthorities, Version: c.vers, ctx: hs.ctx}
		if clientAuthCert, err = c.getClientCertificate(cri); err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		if c.cipherSuite == ECDHE_SM4_CBC_SM3 || c.cipherSuite == ECDHE_SM4_GCM_SM3 {
			if clientEncCert, err = c.getClientKECertificate(cri); err != nil {
				_ = c.sendAlert(alertInternalError)
				return err
			}
		}
		hs.authCert = clientAuthCert
		hs.encCert = clientEncCert
		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}
	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	if certRequested {
		certMsg = new(certificateMsg)
		if len(clientAuthCert.Certificate) > 0 {
			certMsg.certificates = append(certMsg.certificates, clientAuthCert.Certificate[0])
		}
		if c.cipherSuite == ECDHE_SM4_CBC_SM3 || c.cipherSuite == ECDHE_SM4_GCM_SM3 {
			certMsg.certificates = append(certMsg.certificates, clientEncCert.Certificate[0])
		}
		if _, err = c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
			return err
		}
	}
	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(hs)
	if err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		if _, err = c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
			return err
		}
	}
	if clientAuthCert != nil && len(clientAuthCert.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}
		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		signed := hs.finishedHash.Sum()
		certVerify.signature, err = signHandshake(c, sigType, clientAuthCert.PrivateKey, newHash, signed)
		if err != nil {
			_ = c.sendAlert(alertInternalError)
			return err
		}
		if _, err := c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	hs.finishedHash.discardHandshakeBuffer()
	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}
	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	return hs.session != nil &&
		hs.hello.sessionId != nil &&
		len(hs.serverHello.sessionId) > 0 &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c
	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}
	if hs.serverHello.compressionMethod != compressionNone {
		_ = c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tlcp: server selected unsupported compression format")
	}
	if !hs.serverResumedSession() {
		return false, nil
	}
	if hs.session.vers != c.vers {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tlcp: server resumed a session with a different version")
	}
	if hs.session.cipherSuite != hs.suite.id {
		_ = c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tlcp: server resumed a session with a different cipher suite")
	}
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.peerCertificates
	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c
	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}
	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: server's Finished message was incorrect")
	}
	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) createNewSession() error {
	if hs.c.config.SessionCache == nil {
		return nil
	}
	sessionKey := hex.EncodeToString(hs.serverHello.sessionId)
	cs := &SessionState{
		sessionId:        hs.serverHello.sessionId,
		vers:             hs.serverHello.vers,
		cipherSuite:      hs.serverHello.cipherSuite,
		masterSecret:     hs.masterSecret,
		createdAt:        time.Now(),
		peerCertificates: hs.peerCertificates,
	}
	dst := hs.c.conn.RemoteAddr().String()
	hs.c.config.SessionCache.Put(sessionKey, cs)
	hs.c.config.SessionCache.Put(dst, cs)
	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c
	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}
	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	if _, err := c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	activeHandles := make([]*activeCert, len(certificates))
	certs := make([]*smx509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := clientCertCache.newCert(asn1Data)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: failed to parse certificate from server: " + err.Error())
		}
		activeHandles[i] = cert
		certs[i] = cert.cert
	}
	if len(certs) < 2 {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: need two of certificate one for sign one for encrypt")
	}
	if !c.config.InsecureSkipVerify {
		opts := smx509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			DNSName:       c.config.ServerName,
			Intermediates: smx509.NewCertPool(),
		}

		for _, cert := range certs[2:] {
			opts.Intermediates.AddCert(cert)
		}

		var err error
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
		_, err = certs[1].Verify(opts)
		if err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}
	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		break
	default:
		_ = c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tlcp: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}
	c.activeCertHandles = activeHandles
	c.peerCertificates = certs
	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}
	return nil
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}
	if len(c.config.Certificates) > 0 {
		if err := cri.SupportsCertificate(&c.config.Certificates[0]); err == nil {
			return &c.config.Certificates[0], nil
		}
	}
	return new(Certificate), nil
}

func (c *Conn) getClientKECertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientKECertificate != nil {
		return c.config.GetClientKECertificate(cri)
	}
	if len(c.config.Certificates) > 1 {
		if err := cri.SupportsCertificate(&c.config.Certificates[1]); err == nil {
			return &c.config.Certificates[1], nil
		}
	}
	return nil, errNoCertificates
}
