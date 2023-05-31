package tlcp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/aacfactory/afssl/gmsm/ecdh"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/smx509"
)

type keyAgreementProtocol interface {
	generateServerKeyExchange(*serverHandshakeState) (*serverKeyExchangeMsg, error)
	processClientKeyExchange(*serverHandshakeState, *clientKeyExchangeMsg) ([]byte, error)
	processServerKeyExchange(*clientHandshakeState, *serverKeyExchangeMsg) error
	generateClientKeyExchange(*clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error)
}

var errClientKeyExchange = errors.New("tlcp: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tlcp: invalid ServerKeyExchange message")

type eccKeyAgreement struct {
	version      uint16
	privateKey   []byte
	curveid      CurveID
	publicKey    []byte
	x, y         *big.Int
	encipherCert *smx509.Certificate
}

func (e *eccKeyAgreement) generateServerKeyExchange(hs *serverHandshakeState) (*serverKeyExchangeMsg, error) {
	sigCert := hs.sigCert
	encCert := hs.encCert
	if sigCert == nil && encCert == nil {
		return nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	config := hs.c.config
	msg := e.hashForServerKeyExchange(hs.clientHello.random, hs.hello.random, encCert.Certificate[0])
	priv, ok := sigCert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Signer")
	}
	sig, err := priv.Sign(config.rand(), msg, sm2.NewSignerOption(true, nil))
	if err != nil {
		return nil, err
	}
	ske := new(serverKeyExchangeMsg)
	size := len(sig)
	ske.key = make([]byte, size+2)
	ske.key[0] = byte(size >> 8)
	ske.key[1] = byte(size & 0xFF)
	copy(ske.key[2:], sig)
	return ske, nil
}

func (e *eccKeyAgreement) processClientKeyExchange(hs *serverHandshakeState, ckx *clientKeyExchangeMsg) ([]byte, error) {
	sigCert := hs.sigCert
	encCert := hs.encCert
	if sigCert == nil && encCert == nil {
		return nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	config := hs.c.config

	if len(ckx.ciphertext) == 0 {
		return nil, errClientKeyExchange
	}

	size := int(ckx.ciphertext[0]) << 8
	size |= int(ckx.ciphertext[1])

	if 2+size != len(ckx.ciphertext) {
		return nil, errClientKeyExchange
	}

	cipher := ckx.ciphertext[2:]
	if cipher[0] != 0x30 {
		return nil, errors.New("tlcp: bad client key exchange ciphertext format")
	}

	length := 3 + int(cipher[2])
	if len(cipher) >= length {
		cipher = cipher[:length]
	}
	decrypter, ok := encCert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Decrypter")
	}
	plain, err := decrypter.Decrypt(config.rand(), cipher, sm2.ASN1DecryptorOpts)
	if err != nil {
		return nil, err
	}

	if len(plain) != 48 {
		return nil, errClientKeyExchange
	}

	return plain, nil
}

func (e *eccKeyAgreement) processServerKeyExchange(hs *clientHandshakeState, skx *serverKeyExchangeMsg) error {
	if len(hs.peerCertificates) < 2 {
		return errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	sigCert := hs.peerCertificates[0]
	encCert := hs.peerCertificates[1]

	if len(skx.key) <= 2 {
		return errServerKeyExchange
	}
	sigLen := int(skx.key[0]) << 8
	sigLen |= int(skx.key[1])
	if sigLen+2 != len(skx.key) {
		return errServerKeyExchange
	}

	sig := skx.key[2:]

	pub, ok := sigCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: sm2 signing requires a sm2 public key")
	}

	tbs := e.hashForServerKeyExchange(hs.hello.random, hs.serverHello.random, encCert.Raw)

	if !sm2.VerifyASN1WithSM2(pub, nil, tbs, sig) {
		return errors.New("tlcp: processServerKeyExchange: sm2 verification failure")
	}
	return nil
}

func (e *eccKeyAgreement) generateClientKeyExchange(hs *clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error) {
	if len(hs.peerCertificates) < 2 {
		return nil, nil, errors.New("tlcp: ecc key exchange need 2 certificates")
	}
	encCert := hs.peerCertificates[1]
	config := hs.c.config

	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(hs.hello.vers >> 8)
	preMasterSecret[1] = byte(hs.hello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	pub := encCert.PublicKey.(*ecdsa.PublicKey)
	encrypted, err := sm2.Encrypt(config.rand(), pub, preMasterSecret, sm2.ASN1EncryptorOpts)
	if err != nil {
		return nil, nil, err
	}

	ckx := new(clientKeyExchangeMsg)
	size := len(encrypted)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(size >> 8)
	ckx.ciphertext[1] = byte(size & 0xFF)
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

func (e *eccKeyAgreement) hashForServerKeyExchange(clientRandom, serverRandom, cert []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(clientRandom)
	buffer.Write(serverRandom)
	certLen := len(cert)
	buffer.Write([]byte{
		byte(certLen>>16) & 0xFF,
		byte(certLen>>8) & 0xFF,
		byte(certLen),
	})
	buffer.Write(cert)

	return buffer.Bytes()
}

type sm2ECDHEKeyAgreement struct {
	ke         SM2KeyAgreement
	peerTmpKey *ecdh.PublicKey
}

func (ka *sm2ECDHEKeyAgreement) generateServerKeyExchange(hs *serverHandshakeState) (*serverKeyExchangeMsg, error) {
	if hs.sigCert == nil || hs.encCert == nil {
		return nil, errors.New("tlcp: ECDHE key exchange needs 2 certificates")
	}
	config := hs.c.config
	sigkey := hs.sigCert

	encPrv := hs.encCert.PrivateKey
	switch key := encPrv.(type) {
	case SM2KeyAgreement:
		ka.ke = key
	case *sm2.PrivateKey:
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, err
		}
		ka.ke = newSM2KeyKE(config.rand(), ecdhKey)
	default:
		return nil, fmt.Errorf("tlcp: private key not support sm2 key exchange")
	}

	_, sponsorTmpPubKey, err := ka.ke.GenerateAgreementData(nil, 48)
	if err != nil {
		return nil, err
	}

	ecdhePublic := sponsorTmpPubKey.Bytes()
	serverECDHEParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHEParams[0] = 3 // named curve
	serverECDHEParams[1] = byte(CurveSM2 >> 8)
	serverECDHEParams[2] = byte(CurveSM2)
	serverECDHEParams[3] = byte(len(ecdhePublic))
	copy(serverECDHEParams[4:], ecdhePublic)

	buffer := new(bytes.Buffer)
	buffer.Write(hs.clientHello.random)
	buffer.Write(hs.hello.random)
	buffer.Write(serverECDHEParams)
	tbs := buffer.Bytes()
	sigPrv, ok := sigkey.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlcp: certificate private key does not implement crypto.Signer")
	}
	sig, err := sigPrv.Sign(config.rand(), tbs, sm2.NewSignerOption(true, nil))
	if err != nil {
		return nil, err
	}

	skx := new(serverKeyExchangeMsg)
	skx.key = make([]byte, len(serverECDHEParams)+2+len(sig))
	copy(skx.key, serverECDHEParams)
	k := skx.key[len(serverECDHEParams):]
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig) & 0xFF)
	copy(k[2:], sig)

	return skx, nil
}

func getECDHEPublicKey(ciphertext []byte) (*ecdh.PublicKey, error) {
	var pubLenStart int
	switch len(ciphertext) {
	case 69: // fixed structure
		pubLenStart = 3
	case 71: // vector
		pubLenStart = 5
		size := int(ciphertext[0]) << 8
		size |= int(ciphertext[1])

		if 2+size != len(ciphertext) {
			return nil, errClientKeyExchange
		}
	default:
		return nil, errClientKeyExchange
	}
	publicLen := int(ciphertext[pubLenStart])
	if publicLen != len(ciphertext[pubLenStart+1:]) {
		return nil, errClientKeyExchange
	}
	return ecdh.P256().NewPublicKey(ciphertext[pubLenStart+1:])
}

func (ka *sm2ECDHEKeyAgreement) processClientKeyExchange(hs *serverHandshakeState, ckx *clientKeyExchangeMsg) ([]byte, error) {
	if len(hs.peerCertificates) < 2 {
		return nil, errors.New("tlcp: sm2 key exchange need client enc cert")
	}
	responsePubKey, ok := hs.peerCertificates[1].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tlcp: client key not sm2 type")
	}
	responsePubKeyECDH, err := sm2.PublicKeyToECDH(responsePubKey)
	if err != nil {
		return nil, err
	}

	responseTmpPubKey, err := getECDHEPublicKey(ckx.ciphertext)
	if err != nil {
		return nil, err
	}

	return ka.ke.GenerateKey(nil, responsePubKeyECDH, responseTmpPubKey)
}

func (ka *sm2ECDHEKeyAgreement) processServerKeyExchange(hs *clientHandshakeState, skx *serverKeyExchangeMsg) error {
	if len(hs.peerCertificates) < 2 {
		return errors.New("tlcp: sm2 key exchange need server provide two certificate")
	}
	sigCert := hs.peerCertificates[0]
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	tmpPubKey, err := ecdh.P256().NewPublicKey(serverECDHEParams[4:])
	if err != nil {
		return err
	}
	ka.peerTmpKey = tmpPubKey

	signedParams := skx.key[4+publicLen:]
	sigLen := int(signedParams[0]) << 8
	sigLen |= int(signedParams[1])
	if sigLen+2 > len(signedParams) {
		return errServerKeyExchange
	}

	sig := signedParams[2:]
	pub, ok := sigCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tlcp: sm2 signing requires a sm2 public key")
	}

	buffer := new(bytes.Buffer)
	buffer.Write(hs.hello.random)
	buffer.Write(hs.serverHello.random)
	buffer.Write(serverECDHEParams)
	tbs := buffer.Bytes()
	if !sm2.VerifyASN1WithSM2(pub, nil, tbs, sig) {
		return errors.New("tlcp: processServerKeyExchange: sm2 verification failure")
	}
	return nil
}

func (ka *sm2ECDHEKeyAgreement) generateClientKeyExchange(hs *clientHandshakeState) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.peerTmpKey == nil {
		return nil, nil, errServerKeyExchange
	}
	encPriv := hs.encCert.PrivateKey
	switch prvKey := encPriv.(type) {
	case SM2KeyAgreement:
		ka.ke = prvKey
	case *sm2.PrivateKey:
		ecdhPriv, err := prvKey.ECDH()
		if err != nil {
			return nil, nil, err
		}
		ka.ke = newSM2KeyKE(hs.c.config.rand(), ecdhPriv)
	default:
		return nil, nil, fmt.Errorf("tlcp: private key not support sm2 key exchange")
	}

	encCert := hs.peerCertificates[1]
	sponsorPubKey, ok := encCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("tlcp: server encrypt certificate key type not sm2")
	}

	sponsorECDHPubKey, err := sm2.PublicKeyToECDH(sponsorPubKey)
	if err != nil {
		return nil, nil, err
	}
	responseTmpPubKey, preMasterSecret, err := ka.ke.GenerateAgreementDataAndKey(nil, nil, sponsorECDHPubKey, ka.peerTmpKey, 48)
	if err != nil {
		return nil, nil, err
	}

	var params []byte
	ecdhePublic := responseTmpPubKey.Bytes()
	paramLen := 1 + 2 + 1 + len(ecdhePublic)
	ckx := new(clientKeyExchangeMsg)
	if hs.c.config.ClientECDHEParamsAsVector {
		ckx.ciphertext = make([]byte, 2+paramLen)
		ckx.ciphertext[0] = byte(paramLen >> 8)
		ckx.ciphertext[1] = byte(paramLen & 0xFF)
		params = ckx.ciphertext[2:]
	} else {
		ckx.ciphertext = make([]byte, paramLen)
		params = ckx.ciphertext
	}
	params[0] = 3
	params[1] = byte(CurveSM2 >> 8)
	params[2] = byte(CurveSM2)
	params[3] = byte(len(ecdhePublic))
	copy(params[4:], ecdhePublic)

	return preMasterSecret, ckx, nil
}
