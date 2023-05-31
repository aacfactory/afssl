package tlcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/smx509"
	"hash"
	"io"
	"sync/atomic"
	"time"
)

type serverHandshakeState struct {
	c                *Conn
	ctx              context.Context
	clientHello      *clientHelloMsg
	hello            *serverHelloMsg
	suite            *cipherSuite
	ecdheOk          bool
	ecSignOk         bool
	ecDecryptOk      bool
	rsaDecryptOk     bool
	rsaSignOk        bool
	sessionState     *SessionState
	finishedHash     finishedHash
	masterSecret     []byte
	sigCert          *Certificate
	encCert          *Certificate
	peerCertificates []*smx509.Certificate
}

func (c *Conn) serverHandshake(ctx context.Context) error {
	clientHello, err := c.readClientHello(ctx)
	if err != nil {
		return err
	}
	hs := serverHandshakeState{
		c:           c,
		ctx:         ctx,
		clientHello: clientHello,
	}
	return hs.handshake()
}

func (hs *serverHandshakeState) handshake() error {
	var err error
	c := hs.c

	if err = hs.processClientHello(); err != nil {
		return err
	}

	c.buffering = true
	if hs.checkForResumption() {
		c.didResume = true
		if err = hs.doResumeHandshake(); err != nil {
			return err
		}
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err = c.flush(); err != nil {
			return err
		}
		if err = hs.readFinished(nil); err != nil {
			return err
		}
	} else {
		if err = hs.pickCipherSuite(); err != nil {
			return err
		}
		if err = hs.doFullHandshake(); err != nil {
			return err
		}
		if err = hs.establishKeys(); err != nil {
			return err
		}
		if err = hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.buffering = true
		hs.createSessionState()
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

func (c *Conn) readClientHello(ctx context.Context) (*clientHelloMsg, error) {
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}
	var configForClient *Config
	if c.config.GetConfigForClient != nil {
		chi := clientHelloInfo(ctx, c, clientHello)
		if configForClient, err = c.config.GetConfigForClient(chi); err != nil {
			_ = c.sendAlert(alertInternalError)
			return nil, err
		} else if configForClient != nil {
			c.config = configForClient
		}
	}
	clientVersions := supportedVersionsFromMax(clientHello.vers)
	c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
	if !ok {
		_ = c.sendAlert(alertProtocolVersion)
		return nil, fmt.Errorf("tlcp: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers
	return clientHello, nil
}

func (hs *serverHandshakeState) processClientHello() error {
	c := hs.c
	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers
	foundCompression := false
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}
	if !foundCompression {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: client does not support uncompressed connections")
	}
	var err error
	if hs.hello.random, err = c.tlcpRand(); err != nil {
		_ = c.sendAlert(alertInternalError)
		return err
	}

	hs.hello.compressionMethod = compressionNone
	helloInfo := clientHelloInfo(hs.ctx, c, hs.clientHello)
	hs.sigCert, err = c.config.getCertificate(helloInfo)
	if err != nil {
		if err == errNoCertificates {
			_ = c.sendAlert(alertUnrecognizedName)
		} else {
			_ = c.sendAlert(alertInternalError)
		}
		return err
	}
	hs.encCert, err = c.config.getEKCertificate(helloInfo)
	if err != nil {
		if err == errNoCertificates {
			_ = c.sendAlert(alertUnrecognizedName)
		} else {
			_ = c.sendAlert(alertInternalError)
		}
		return err
	}

	if hs.encCert == nil || hs.sigCert == nil {
		_ = c.sendAlert(alertInternalError)
	}

	if priv, ok := hs.sigCert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("tlcp: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.encCert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecDecryptOk = true
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			_ = c.sendAlert(alertInternalError)
			return fmt.Errorf("tlcp: unsupported decryption key type (%T)", priv.Public())
		}
	}

	return nil
}

func (hs *serverHandshakeState) pickCipherSuite() error {
	c := hs.c
	preferenceOrder := cipherSuitesPreferenceOrder
	configCipherSuites := c.config.cipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))
	for _, suiteID := range preferenceOrder {
		for _, id := range configCipherSuites {
			if id == suiteID {
				preferenceList = append(preferenceList, id)
				break
			}
		}
	}
	hs.suite = selectCipherSuite(preferenceList, hs.clientHello.cipherSuites, hs.cipherSuiteOk)
	if hs.suite == nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id
	return nil
}

func (hs *serverHandshakeState) cipherSuiteOk(c *cipherSuite) bool {
	if c.flags&suiteECSign != 0 {
		if !hs.ecSignOk {
			return false
		}
		if !hs.ecDecryptOk {
			return false
		}
	} else if c.flags&suiteECDHE != 0 {
		if !hs.ecdheOk {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !hs.ecSignOk {
				return false
			}
		} else if !hs.rsaSignOk {
			return false
		}
	} else if !hs.rsaDecryptOk {
		return false
	}
	return true
}

func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c
	if hs.c.config.SessionCache == nil {
		return false
	}
	if len(hs.clientHello.sessionId) == 0 {
		return false
	}
	sessionKey := hex.EncodeToString(hs.clientHello.sessionId)
	var ok bool
	hs.sessionState, ok = hs.c.config.SessionCache.Get(sessionKey)
	if !ok {
		return false
	}

	if c.vers != hs.sessionState.vers {
		return false
	}
	cipherSuiteOk := false
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}
	hs.suite = selectCipherSuite([]uint16{hs.sessionState.cipherSuite},
		c.config.cipherSuites(), hs.cipherSuiteOk)
	if hs.suite == nil {
		return false
	}
	return true
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	c.cipherSuite = hs.suite.id
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	c.peerCertificates = hs.sessionState.peerCertificates

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	hs.hello.sessionId = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.sessionId); err != nil {
		return errors.New("tlcp: error in generate server side session id, " + err.Error())
	}
	authPolice := c.config.ClientAuth
	if hs.suite.id == ECDHE_SM4_CBC_SM3 || hs.suite.id == ECDHE_SM4_GCM_SM3 {
		if authPolice != RequestClientCert {
			authPolice = RequireAndVerifyClientCert
		}
	}

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if authPolice == NoClientCert {
		hs.finishedHash.discardHandshakeBuffer()
	}
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := hs.c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	certMsg := new(certificateMsg)
	certMsg.certificates = [][]byte{
		hs.sigCert.Certificate[0], hs.encCert.Certificate[0],
	}
	if len(hs.sigCert.Certificate) > 1 {
		certMsg.certificates = append(certMsg.certificates, hs.sigCert.Certificate[1:]...)
	} else if len(hs.encCert.Certificate) > 1 {
		certMsg.certificates = append(certMsg.certificates, hs.encCert.Certificate[1:]...)
	}
	if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
		return err
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(hs)
	if err != nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		if _, err := hs.c.writeHandshakeRecord(skx, &hs.finishedHash); err != nil {
			return err
		}
	}

	var certReq *certificateRequestMsg
	if authPolice >= RequestClientCert {
		certReq = new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		if _, err := hs.c.writeHandshakeRecord(certReq, &hs.finishedHash); err != nil {
			return err
		}
	}

	helloDone := new(serverHelloDoneMsg)
	if _, err := hs.c.writeHandshakeRecord(helloDone, &hs.finishedHash); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	if authPolice >= RequestClientCert {
		clientCertMsg, ok := msg.(*certificateMsg)
		if !ok {
			_ = c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(clientCertMsg, msg)
		}

		if err := c.processCertsFromClient(Certificate{Certificate: clientCertMsg.certificates}); err != nil {
			return err
		}
		if len(clientCertMsg.certificates) != 0 {
			pub = c.peerCertificates[0].PublicKey
		}
		hs.peerCertificates = c.peerCertificates
		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}

	preMasterSecret, err := keyAgreement.processClientKeyExchange(hs, ckx)
	if err != nil {
		_ = c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)

	if len(c.peerCertificates) > 0 {
		msg, err = c.readHandshake(nil)
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			_ = c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}
		sigType, newHash, err := typeAndHashFrom(hs.suite.id)
		if err != nil {
			_ = c.sendAlert(alertIllegalParameter)
			return err
		}

		signed := hs.finishedHash.Sum()
		if err := verifyHandshakeSignature(sigType, pub, newHash, signed, certVerify.signature); err != nil {
			_ = c.sendAlert(alertDecryptError)
			return errors.New("tlcp: invalid signature by the client certificate: " + err.Error())
		}

		if err := transcriptMsg(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()
	return nil
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash hash.Hash

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		_ = c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		_ = c.sendAlert(alertHandshakeFailure)
		return errors.New("tlcp: client's Finished message is incorrect")
	}

	if err := transcriptMsg(clientFinished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, verify)
	return nil
}

func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, finished.verifyData)

	return nil
}

func (hs *serverHandshakeState) createSessionState() {
	if hs.c.config.SessionCache == nil {
		return
	}

	sessionKey := hex.EncodeToString(hs.hello.sessionId)
	cs := &SessionState{
		sessionId:        hs.hello.sessionId,
		vers:             hs.hello.vers,
		cipherSuite:      hs.hello.cipherSuite,
		masterSecret:     hs.masterSecret,
		peerCertificates: hs.peerCertificates,
		createdAt:        time.Now(),
	}
	hs.c.config.SessionCache.Put(sessionKey, cs)
}

func (c *Conn) processCertsFromClient(certificate Certificate) error {
	// WARNING: NOT SAFE
	certificates := certificate.Certificate
	certs := make([]*smx509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = smx509.ParseCertificate(asn1Data); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return errors.New("tlcp: failed to parse client certificate: " + err.Error())
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: client didn't provide a certificate")
	}

	isECDHE := c.cipherSuite == ECDHE_SM4_CBC_SM3 || c.cipherSuite == ECDHE_SM4_GCM_SM3
	if len(certs) < 2 && isECDHE {
		_ = c.sendAlert(alertBadCertificate)
		return errors.New("tlcp: client didn't provide both sign/enc certificates for ECDHE suite")
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		keyUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		if c.config.ClientAuth == RequireAndVerifyAnyKeyUsageClientCert {
			keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
		opts := smx509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: smx509.NewCertPool(),
			KeyUsages:     keyUsages,
		}

		start := 1
		if isECDHE {
			start = 2
		}
		for _, cert := range certs[start:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			var errCertificateInvalid x509.CertificateInvalidError
			if errors.As(err, &x509.UnknownAuthorityError{}) {
				_ = c.sendAlert(alertUnknownCA)
			} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == x509.Expired {
				_ = c.sendAlert(alertCertificateExpired)
			} else {
				_ = c.sendAlert(alertBadCertificate)
			}
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}

		if isECDHE {
			_, err = certs[1].Verify(opts)
			if err != nil {
				var errCertificateInvalid x509.CertificateInvalidError
				if errors.As(err, &x509.UnknownAuthorityError{}) {
					_ = c.sendAlert(alertUnknownCA)
				} else if errors.As(err, &errCertificateInvalid) && errCertificateInvalid.Reason == x509.Expired {
					_ = c.sendAlert(alertCertificateExpired)
				} else {
					_ = c.sendAlert(alertBadCertificate)
				}
				return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
			}
		}

		c.verifiedChains = chains
	}

	c.peerCertificates = certs

	if len(certs) > 0 {
		switch certs[0].PublicKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey:
		default:
			_ = c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tlcp: client auth certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
		if isECDHE {
			switch certs[1].PublicKey.(type) {
			case *ecdsa.PublicKey, *rsa.PublicKey:
			default:
				_ = c.sendAlert(alertUnsupportedCertificate)
				return fmt.Errorf("tlcp: client enc certificate contains an unsupported public key of type %T", certs[1].PublicKey)
			}
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			_ = c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVers := supportedVersionsFromMax(clientHello.vers)
	return &ClientHelloInfo{
		CipherSuites:      clientHello.cipherSuites,
		SupportedVersions: supportedVers,
		Conn:              c.conn,
		config:            c.config,
		ctx:               ctx,
	}
}

func (c *Conn) tlcpRand() ([]byte, error) {
	rd := make([]byte, 32)
	_, err := io.ReadFull(c.config.rand(), rd)
	if err != nil {
		return nil, err
	}
	unixTime := time.Now().Unix()
	rd[0] = uint8(unixTime >> 24)
	rd[1] = uint8(unixTime >> 16)
	rd[2] = uint8(unixTime >> 8)
	rd[3] = uint8(unixTime)
	return rd, nil
}
