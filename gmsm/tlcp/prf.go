package tlcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"hash"
)

func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

const (
	masterSecretLength   = 48
	finishedVerifyLength = 12
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

func prfAndHashForVersion(version uint16, suite *cipherSuite) (func(result, secret, label, seed []byte), func() hash.Hash) {
	switch version {
	case VersionTLCP:
		switch suite.id {
		case TLCP_ECDHE_SM4_CBC_SM3,
			TLCP_ECDHE_SM4_GCM_SM3,
			TLCP_ECC_SM4_CBC_SM3,
			TLCP_ECC_SM4_GCM_SM3,
			TLCP_IBSDH_SM4_CBC_SM3,
			TLCP_IBSDH_SM4_GCM_SM3,
			TLCP_IBC_SM4_CBC_SM3,
			TLCP_IBC_SM4_GCM_SM3,
			TLCP_RSA_SM4_CBC_SM3,
			TLCP_RSA_SM4_GCM_SM3:
			return prf12(sm3.New), sm3.New
		case TLCP_RSA_SM4_CBC_SHA256,
			TLCP_RSA_SM4_GCM_SHA256:
			return prf12(sm3.New), sha256.New
		default:
			panic("unknown suite hash")
		}
	default:
		panic("unknown version")
	}
}

func prfForVersion(version uint16, suite *cipherSuite) func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion(version, suite)
	return prf
}

func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed)
	return masterSecret
}

func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion(version, suite)(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

func newFinishedHash(version uint16, cipherSuite *cipherSuite) finishedHash {
	prf, newH := prfAndHashForVersion(version, cipherSuite)
	if newH != nil {
		return finishedHash{newH(), version, prf}
	}
	return finishedHash{sm3.New(), version, prf}
}

type finishedHash struct {
	msgHash hash.Hash
	version uint16
	prf     func(result, secret, label, seed []byte)
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.msgHash.Write(msg)
	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	return h.msgHash.Sum(nil)
}

func (h finishedHash) clientSum(masterSecret []byte) []byte {
	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, clientFinishedLabel, h.Sum())
	return out
}

func (h finishedHash) serverSum(masterSecret []byte) []byte {
	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, serverFinishedLabel, h.Sum())
	return out
}

func (h *finishedHash) discardHandshakeBuffer() {}
