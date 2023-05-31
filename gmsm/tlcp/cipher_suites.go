package tlcp

import (
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"github.com/aacfactory/afssl/gmsm/sm4"
	"hash"
)

type CipherSuite struct {
	ID                uint16
	Name              string
	SupportedVersions []uint16
	Insecure          bool
}

var (
	supportedOnlyTLCP = []uint16{VersionTLCP}
)

func CipherSuites() []*CipherSuite {
	return []*CipherSuite{
		{ECDHE_SM4_CBC_SM3, "ECDHE_SM4_CBC_SM3", supportedOnlyTLCP, false},
		{ECDHE_SM4_GCM_SM3, "ECDHE_SM4_GCM_SM3", supportedOnlyTLCP, false},
		{ECC_SM4_CBC_SM3, "ECC_SM4_CBC_SM3", supportedOnlyTLCP, false},
		{ECC_SM4_GCM_SM3, "ECC_SM4_GCM_SM3", supportedOnlyTLCP, false},
	}
}

func InsecureCipherSuites() []*CipherSuite {
	return []*CipherSuite{}
}

func CipherSuiteName(id uint16) string {
	for _, c := range CipherSuites() {
		if c.ID == id {
			return c.Name
		}
	}
	for _, c := range InsecureCipherSuites() {
		if c.ID == id {
			return c.Name
		}
	}
	return fmt.Sprintf("0x%04X", id)
}

const (
	suiteECDHE = 1 << iota
	suiteECSign
)

type cipherSuite struct {
	id     uint16
	keyLen int
	macLen int
	ivLen  int
	ka     func(version uint16) keyAgreementProtocol
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(key []byte) hash.Hash
	aead   func(key, fixedNonce []byte) aead
}

var cipherSuites = map[uint16]*cipherSuite{
	ECC_SM4_GCM_SM3: {ECC_SM4_GCM_SM3, 16, 0, 4, eccKA, suiteECSign, nil, nil, aeadSM4GCM},
	ECC_SM4_CBC_SM3: {ECC_SM4_CBC_SM3, 16, 32, 16, eccKA, suiteECSign, cipherSM4, macSM3, nil},

	ECDHE_SM4_GCM_SM3: {ECDHE_SM4_GCM_SM3, 16, 0, 4, ecdhKA, suiteECSign | suiteECDHE, nil, nil, aeadSM4GCM},
	ECDHE_SM4_CBC_SM3: {ECDHE_SM4_CBC_SM3, 16, 32, 16, ecdhKA, suiteECSign | suiteECDHE, cipherSM4, macSM3, nil},
}

func selectCipherSuite(ids, supportedIDs []uint16, ok func(*cipherSuite) bool) *cipherSuite {
	for _, id := range ids {
		candidate := cipherSuites[id]
		if candidate == nil || !ok(candidate) {
			continue
		}

		for _, suppID := range supportedIDs {
			if id == suppID {
				return candidate
			}
		}
	}
	return nil
}

var cipherSuitesPreferenceOrder = []uint16{
	ECC_SM4_GCM_SM3,
	ECC_SM4_CBC_SM3,
	ECDHE_SM4_GCM_SM3,
	ECDHE_SM4_CBC_SM3,
}

var disabledCipherSuites = []uint16{}

var (
	defaultCipherSuitesLen = len(cipherSuitesPreferenceOrder) - len(disabledCipherSuites)
	defaultCipherSuites    = cipherSuitesPreferenceOrder[:defaultCipherSuitesLen]
)

func tls10MAC(h hash.Hash, out, seq, header, data, extra []byte) []byte {
	h.Reset()
	h.Write(seq)
	h.Write(header)
	h.Write(data)
	res := h.Sum(out)
	if extra != nil {
		h.Write(extra)
	}
	return res
}

func mutualCipherSuite(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			return cipherSuites[id]
		}
	}
	return nil
}

const (
	TLCP_ECDHE_SM4_CBC_SM3  uint16 = 0xe011
	TLCP_ECDHE_SM4_GCM_SM3  uint16 = 0xe051
	TLCP_ECC_SM4_CBC_SM3    uint16 = 0xe013
	TLCP_ECC_SM4_GCM_SM3    uint16 = 0xe053
	TLCP_IBSDH_SM4_CBC_SM3  uint16 = 0xe015
	TLCP_IBSDH_SM4_GCM_SM3  uint16 = 0xe055
	TLCP_IBC_SM4_CBC_SM3    uint16 = 0xe017
	TLCP_IBC_SM4_GCM_SM3    uint16 = 0xe057
	TLCP_RSA_SM4_CBC_SM3    uint16 = 0xe019
	TLCP_RSA_SM4_GCM_SM3    uint16 = 0xe059
	TLCP_RSA_SM4_CBC_SHA256 uint16 = 0xe01e
	TLCP_RSA_SM4_GCM_SHA256 uint16 = 0xe05a

	ECDHE_SM4_CBC_SM3  uint16 = 0xe011
	ECDHE_SM4_GCM_SM3  uint16 = 0xe051
	ECC_SM4_CBC_SM3    uint16 = 0xe013
	ECC_SM4_GCM_SM3    uint16 = 0xe053
	IBSDH_SM4_CBC_SM3  uint16 = 0xe015
	IBSDH_SM4_GCM_SM3  uint16 = 0xe055
	IBC_SM4_CBC_SM3    uint16 = 0xe017
	IBC_SM4_GCM_SM3    uint16 = 0xe057
	RSA_SM4_CBC_SM3    uint16 = 0xe019
	RSA_SM4_GCM_SM3    uint16 = 0xe059
	RSA_SM4_CBC_SHA256 uint16 = 0xe01e
	RSA_SM4_GCM_SHA256 uint16 = 0xe05a
)

type SignatureAlgorithm uint16

const (
	NONE       SignatureAlgorithm = 0
	RSA_SHA256 SignatureAlgorithm = 1
	RSA_SM3    SignatureAlgorithm = 2
	ECC_SM3    SignatureAlgorithm = 3
	IBS_SM3    SignatureAlgorithm = 4
)

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

type aead interface {
	cipher.AEAD
	explicitNonceLen() int
}

type prefixNonceAEAD struct {
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

func eccKA(version uint16) keyAgreementProtocol {
	return &eccKeyAgreement{
		version: version,
	}
}

func ecdhKA(version uint16) keyAgreementProtocol {
	return &sm2ECDHEKeyAgreement{}
}

func cipherSM4(key, iv []byte, isRead bool) interface{} {
	block, _ := sm4.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func macSM3(key []byte) hash.Hash {
	return hmac.New(sm3.New, key)
}

func aeadSM4GCM(key []byte, nonce []byte) aead {
	if len(nonce) != noncePrefixLength {
		panic("tls: internal error: wrong implicit nonce length")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err)
	}
	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], nonce)
	return ret
}
