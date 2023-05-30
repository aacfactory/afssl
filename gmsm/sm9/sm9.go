// Package sm9 implements ShangMi(SM) sm9 digital signature, encryption and key exchange algorithms.
package sm9

import (
	"crypto"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/aacfactory/afssl/gmsm/internal/bigmod"
	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"github.com/aacfactory/afssl/gmsm/sm9/bn256"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var orderNat = bigmod.NewModulusFromBig(bn256.Order)
var orderMinus2 = new(big.Int).Sub(bn256.Order, big.NewInt(2)).Bytes()
var bigOne = big.NewInt(1)
var bigOneNat *bigmod.Nat
var orderMinus1 = bigmod.NewNat().SetBig(new(big.Int).Sub(bn256.Order, bigOne))

func init() {
	bigOneNat, _ = bigmod.NewNat().SetBytes(bigOne.Bytes(), orderNat)
}

type hashMode byte

const (
	H1 hashMode = 1 + iota
	H2
)

type encryptType byte

const (
	EncTypeXor encryptType = 0
	EncTypeEcb encryptType = 1
	EncTypeCbc encryptType = 2
	EncTypeOfb encryptType = 4
	EncTypeCfb encryptType = 8
)

func hash(z []byte, h hashMode) *bigmod.Nat {
	md := sm3.New()
	var ha [64]byte
	var countBytes [4]byte
	var ct uint32 = 1

	for i := 0; i < 2; i++ {
		binary.BigEndian.PutUint32(countBytes[:], ct)
		md.Write([]byte{byte(h)})
		md.Write(z)
		md.Write(countBytes[:])
		copy(ha[i*sm3.Size:], md.Sum(nil))
		ct++
		md.Reset()
	}
	k := new(big.Int).SetBytes(ha[:40])
	kNat := bigmod.NewNat().SetBig(k)
	kNat = bigmod.NewNat().ModNat(kNat, orderMinus1)
	kNat.Add(bigOneNat, orderNat)
	return kNat
}

func hashH1(z []byte) *bigmod.Nat {
	return hash(z, H1)
}

func hashH2(z []byte) *bigmod.Nat {
	return hash(z, H2)
}

func randomScalar(rand io.Reader) (k *bigmod.Nat, err error) {
	k = bigmod.NewNat()
	for {
		b := make([]byte, orderNat.Size())
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}

		if excess := len(b)*8 - orderNat.BitLen(); excess > 0 {
			if excess != 0 {
				panic("sm9: internal error: unexpectedly masking off bits")
			}
			b[0] >>= excess
		}

		if _, err = k.SetBytes(b, orderNat); err == nil && k.IsZero() == 0 {
			break
		}
	}
	return
}

func Sign(rand io.Reader, priv *SignPrivateKey, hash []byte) (h *big.Int, s *bn256.G1, err error) {
	sig, err := SignASN1(rand, priv, hash)
	if err != nil {
		return nil, nil, err
	}
	return parseSignatureLegacy(sig)
}

func (priv *SignPrivateKey) Sign(rand io.Reader, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignASN1(rand, priv, hash)
}

func SignASN1(rand io.Reader, priv *SignPrivateKey, hash []byte) ([]byte, error) {
	var (
		hNat *bigmod.Nat
		s    *bn256.G1
	)
	for {
		r, err := randomScalar(rand)
		if err != nil {
			return nil, err
		}

		w, err := priv.SignMasterPublicKey.ScalarBaseMult(r.Bytes(orderNat))
		if err != nil {
			return nil, err
		}

		var buffer []byte
		buffer = append(buffer, hash...)
		buffer = append(buffer, w.Marshal()...)

		hNat = hashH2(buffer)
		r.Sub(hNat, orderNat)

		if r.IsZero() == 0 {
			s, err = new(bn256.G1).ScalarMult(priv.PrivateKey, r.Bytes(orderNat))
			if err != nil {
				return nil, err
			}
			break
		}
	}

	return encodeSignature(hNat.Bytes(orderNat), s)
}

func Verify(pub *SignMasterPublicKey, uid []byte, hid byte, hash []byte, h *big.Int, s *bn256.G1) bool {
	if h.Sign() <= 0 {
		return false
	}
	sig, err := encodeSignature(h.Bytes(), s)
	if err != nil {
		return false
	}
	return VerifyASN1(pub, uid, hid, hash, sig)
}

func encodeSignature(hBytes []byte, s *bn256.G1) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(hBytes)
		b.AddASN1BitString(s.MarshalUncompressed())
	})
	return b.Bytes()
}

func parseSignature(sig []byte) ([]byte, *bn256.G1, error) {
	var (
		hBytes []byte
		sBytes []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Bytes(&hBytes, asn1.OCTET_STRING) ||
		!inner.ReadASN1BitStringAsBytes(&sBytes) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	if sBytes[0] != 4 {
		return nil, nil, errors.New("sm9: invalid point format")
	}
	s := new(bn256.G1)
	_, err := s.Unmarshal(sBytes[1:])
	if err != nil {
		return nil, nil, err
	}
	return hBytes, s, nil
}

func parseSignatureLegacy(sig []byte) (*big.Int, *bn256.G1, error) {
	hBytes, s, err := parseSignature(sig)
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(hBytes), s, nil
}

func VerifyASN1(pub *SignMasterPublicKey, uid []byte, hid byte, hash, sig []byte) bool {
	h, s, err := parseSignature(sig)
	if err != nil {
		return false
	}
	if !s.IsOnCurve() {
		return false
	}

	hNat, err := bigmod.NewNat().SetBytes(h, orderNat)
	if err != nil {
		return false
	}
	if hNat.IsZero() == 1 {
		return false
	}

	t, err := pub.ScalarBaseMult(hNat.Bytes(orderNat))
	if err != nil {
		return false
	}

	// user sign public key p generation
	p := pub.GenerateUserPublicKey(uid, hid)

	u := bn256.Pair(s, p)
	w := new(bn256.GT).Add(u, t)

	var buffer []byte
	buffer = append(buffer, hash...)
	buffer = append(buffer, w.Marshal()...)
	h2 := hashH2(buffer)

	return h2.Equal(hNat) == 1
}

func (pub *SignMasterPublicKey) Verify(uid []byte, hid byte, hash, sig []byte) bool {
	return VerifyASN1(pub, uid, hid, hash, sig)
}

func WrapKey(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, kLen int) (key []byte, cipher *bn256.G1, err error) {
	q := pub.GenerateUserPublicKey(uid, hid)
	var (
		r *bigmod.Nat
		w *bn256.GT
	)
	for {
		r, err = randomScalar(rand)
		if err != nil {
			return
		}

		rBytes := r.Bytes(orderNat)
		cipher, err = new(bn256.G1).ScalarMult(q, rBytes)
		if err != nil {
			return
		}

		w, err = pub.ScalarBaseMult(rBytes)
		if err != nil {
			return
		}
		var buffer []byte
		buffer = append(buffer, cipher.Marshal()...)
		buffer = append(buffer, w.Marshal()...)
		buffer = append(buffer, uid...)

		key = kdf.Kdf(sm3.New(), buffer, kLen)
		if subtle.ConstantTimeCompare(key, nil) != 1 {
			break
		}
	}
	return
}

func (pub *EncryptMasterPublicKey) WrapKey(rand io.Reader, uid []byte, hid byte, kLen int) ([]byte, []byte, error) {
	key, cipher, err := WrapKey(rand, pub, uid, hid, kLen)
	if err != nil {
		return nil, nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1BitString(cipher.MarshalUncompressed())
	cipherASN1, err := b.Bytes()

	return key, cipherASN1, err
}

func (pub *EncryptMasterPublicKey) WrapKeyASN1(rand io.Reader, uid []byte, hid byte, kLen int) ([]byte, error) {
	key, cipher, err := WrapKey(rand, pub, uid, hid, kLen)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(key)
		b.AddASN1BitString(cipher.MarshalUncompressed())
	})
	return b.Bytes()
}

func UnmarshalSM9KeyPackage(der []byte) ([]byte, *bn256.G1, error) {
	input := cryptobyte.String(der)
	var (
		key         []byte
		cipherBytes []byte
		inner       cryptobyte.String
	)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Bytes(&key, asn1.OCTET_STRING) ||
		!inner.ReadASN1BitStringAsBytes(&cipherBytes) ||
		!inner.Empty() {
		return nil, nil, errors.New("sm9: invalid SM9KeyPackage asn.1 data")
	}
	g, err := unmarshalG1(cipherBytes)
	if err != nil {
		return nil, nil, err
	}
	return key, g, nil
}

var ErrDecryption = errors.New("sm9: decryption error")

var ErrEmptyPlaintext = errors.New("sm9: empty plaintext")

func UnwrapKey(priv *EncryptPrivateKey, uid []byte, cipher *bn256.G1, kLen int) ([]byte, error) {
	if !cipher.IsOnCurve() {
		return nil, ErrDecryption
	}

	w := bn256.Pair(cipher, priv.PrivateKey)

	var buffer []byte
	buffer = append(buffer, cipher.Marshal()...)
	buffer = append(buffer, w.Marshal()...)
	buffer = append(buffer, uid...)

	key := kdf.Kdf(sm3.New(), buffer, kLen)
	if subtle.ConstantTimeCompare(key, nil) == 1 {
		return nil, ErrDecryption
	}
	return key, nil
}

func (priv *EncryptPrivateKey) UnwrapKey(uid, cipherDer []byte, kLen int) ([]byte, error) {
	var bytes []byte
	input := cryptobyte.String(cipherDer)
	if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return nil, ErrDecryption
	}
	g, err := unmarshalG1(bytes)
	if err != nil {
		return nil, ErrDecryption
	}
	return UnwrapKey(priv, uid, g, kLen)
}

func Encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
	if err != nil {
		return nil, err
	}
	ciphertext := append(c1.Marshal(), c3...)
	ciphertext = append(ciphertext, c2...)
	return ciphertext, nil
}

func encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) (c1 *bn256.G1, c2, c3 []byte, err error) {
	if opts == nil {
		opts = DefaultEncrypterOpts
	}
	if len(plaintext) == 0 {
		return nil, nil, nil, ErrEmptyPlaintext
	}
	key1Len := opts.GetKeySize(plaintext)
	key, c1, err := WrapKey(rand, pub, uid, hid, key1Len+sm3.Size)
	if err != nil {
		return nil, nil, nil, err
	}
	c2, err = opts.Encrypt(rand, key[:key1Len], plaintext)
	if err != nil {
		return nil, nil, nil, err
	}

	hash := sm3.New()
	hash.Write(c2)
	hash.Write(key[key1Len:])
	c3 = hash.Sum(nil)

	return
}

func EncryptASN1(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	return pub.Encrypt(rand, uid, hid, plaintext, opts)
}

func (pub *EncryptMasterPublicKey) Encrypt(rand io.Reader, uid []byte, hid byte, plaintext []byte, opts EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = DefaultEncrypterOpts
	}
	c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(opts.GetEncryptType()))
		b.AddASN1BitString(c1.MarshalUncompressed())
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

func Decrypt(priv *EncryptPrivateKey, uid, ciphertext []byte, opts EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = DefaultEncrypterOpts
	}

	c := &bn256.G1{}
	c3c2, err := c.Unmarshal(ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}

	c2 := c3c2[sm3.Size:]
	key1Len := opts.GetKeySize(c2)

	key, err := UnwrapKey(priv, uid, c, key1Len+sm3.Size)
	if err != nil {
		return nil, err
	}

	return decrypt(c, key[:key1Len], key[key1Len:], c2, c3c2[:sm3.Size], opts)
}

func decrypt(cipher *bn256.G1, key1, key2, c2, c3 []byte, opts EncrypterOpts) ([]byte, error) {
	hash := sm3.New()
	hash.Write(c2)
	hash.Write(key2)
	c32 := hash.Sum(nil)

	if subtle.ConstantTimeCompare(c3, c32) != 1 {
		return nil, ErrDecryption
	}

	return opts.Decrypt(key1, c2)
}

func DecryptASN1(priv *EncryptPrivateKey, uid, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= 32+65 {
		return nil, errors.New("sm9: ciphertext too short")
	}
	var (
		encType int
		c3Bytes []byte
		c1Bytes []byte
		c2Bytes []byte
		inner   cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&encType) ||
		!inner.ReadASN1BitStringAsBytes(&c1Bytes) ||
		!inner.ReadASN1Bytes(&c3Bytes, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2Bytes, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, errors.New("sm9: invalid ciphertext asn.1 data")
	}
	opts := shangMiEncrypterOpts(encryptType(encType))
	if opts == nil {
		return nil, ErrDecryption
	}
	c, err := unmarshalG1(c1Bytes)
	if err != nil {
		return nil, ErrDecryption
	}

	key1Len := opts.GetKeySize(c2Bytes)
	key, err := UnwrapKey(priv, uid, c, key1Len+sm3.Size)
	if err != nil {
		return nil, err
	}

	return decrypt(c, key[:key1Len], key[key1Len:], c2Bytes, c3Bytes, opts)
}

func (priv *EncryptPrivateKey) Decrypt(uid, ciphertext []byte, opts EncrypterOpts) ([]byte, error) {
	return Decrypt(priv, uid, ciphertext, opts)
}

func (priv *EncryptPrivateKey) DecryptASN1(uid, ciphertext []byte) ([]byte, error) {
	return DecryptASN1(priv, uid, ciphertext)
}

type KeyExchange struct {
	genSignature bool
	keyLength    int
	privateKey   *EncryptPrivateKey
	uid          []byte
	peerUID      []byte
	r            *bigmod.Nat
	secret       *bn256.G1
	peerSecret   *bn256.G1
	g1           *bn256.GT
	g2           *bn256.GT
	g3           *bn256.GT
}

func NewKeyExchange(priv *EncryptPrivateKey, uid, peerUID []byte, keyLen int, genSignature bool) *KeyExchange {
	ke := &KeyExchange{}
	ke.genSignature = genSignature
	ke.keyLength = keyLen
	ke.privateKey = priv
	ke.uid = uid
	ke.peerUID = peerUID
	return ke
}

func (ke *KeyExchange) Destroy() {
	if ke.r != nil {
		ke.r.SetBytes([]byte{0}, orderNat)
	}
	if ke.g1 != nil {
		ke.g1.SetOne()
	}
	if ke.g2 != nil {
		ke.g2.SetOne()
	}
	if ke.g3 != nil {
		ke.g3.SetOne()
	}
}

func initKeyExchange(ke *KeyExchange, hid byte, r *bigmod.Nat) {
	pubB := ke.privateKey.GenerateUserPublicKey(ke.peerUID, hid)
	ke.r = r
	rA, err := new(bn256.G1).ScalarMult(pubB, ke.r.Bytes(orderNat))
	if err != nil {
		panic(err)
	}
	ke.secret = rA
}

func (ke *KeyExchange) Init(rand io.Reader, hid byte) (*bn256.G1, error) {
	r, err := randomScalar(rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, hid, r)
	return ke.secret, nil
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
	var buffer []byte
	hash := sm3.New()
	hash.Write(ke.g2.Marshal())
	hash.Write(ke.g3.Marshal())
	if isResponder {
		hash.Write(ke.peerUID)
		hash.Write(ke.uid)
		hash.Write(ke.peerSecret.Marshal())
		hash.Write(ke.secret.Marshal())
	} else {
		hash.Write(ke.uid)
		hash.Write(ke.peerUID)
		hash.Write(ke.secret.Marshal())
		hash.Write(ke.peerSecret.Marshal())
	}
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{prefix})
	hash.Write(ke.g1.Marshal())
	hash.Write(buffer)
	return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) ([]byte, error) {
	var buffer []byte
	if isResponder {
		buffer = append(buffer, ke.peerUID...)
		buffer = append(buffer, ke.uid...)
		buffer = append(buffer, ke.peerSecret.Marshal()...)
		buffer = append(buffer, ke.secret.Marshal()...)
	} else {
		buffer = append(buffer, ke.uid...)
		buffer = append(buffer, ke.peerUID...)
		buffer = append(buffer, ke.secret.Marshal()...)
		buffer = append(buffer, ke.peerSecret.Marshal()...)
	}
	buffer = append(buffer, ke.g1.Marshal()...)
	buffer = append(buffer, ke.g2.Marshal()...)
	buffer = append(buffer, ke.g3.Marshal()...)

	return kdf.Kdf(sm3.New(), buffer, ke.keyLength), nil
}

func respondKeyExchange(ke *KeyExchange, hid byte, r *bigmod.Nat, rA *bn256.G1) (*bn256.G1, []byte, error) {
	if !rA.IsOnCurve() {
		return nil, nil, errors.New("sm9: invalid initiator's ephemeral public key")
	}
	ke.peerSecret = rA
	pubA := ke.privateKey.GenerateUserPublicKey(ke.peerUID, hid)
	ke.r = r
	rBytes := r.Bytes(orderNat)
	rB, err := new(bn256.G1).ScalarMult(pubA, rBytes)
	if err != nil {
		return nil, nil, err
	}
	ke.secret = rB

	ke.g1 = bn256.Pair(ke.peerSecret, ke.privateKey.PrivateKey)
	ke.g3 = &bn256.GT{}
	g3, err := bn256.ScalarMultGT(ke.g1, rBytes)
	if err != nil {
		return nil, nil, err
	}
	ke.g3 = g3

	g2, err := ke.privateKey.EncryptMasterPublicKey.ScalarBaseMult(rBytes)
	if err != nil {
		return nil, nil, err
	}
	ke.g2 = g2

	if !ke.genSignature {
		return ke.secret, nil, nil
	}

	return ke.secret, ke.sign(true, 0x82), nil
}

func (ke *KeyExchange) Respond(rand io.Reader, hid byte, rA *bn256.G1) (*bn256.G1, []byte, error) {
	r, err := randomScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	return respondKeyExchange(ke, hid, r, rA)
}

func (ke *KeyExchange) ConfirmResponder(rB *bn256.G1, sB []byte) ([]byte, []byte, error) {
	if !rB.IsOnCurve() {
		return nil, nil, errors.New("sm9: invalid responder's ephemeral public key")
	}
	// step 5
	ke.peerSecret = rB
	g1, err := ke.privateKey.EncryptMasterPublicKey.ScalarBaseMult(ke.r.Bytes(orderNat))
	if err != nil {
		return nil, nil, err
	}
	ke.g1 = g1
	ke.g2 = bn256.Pair(ke.peerSecret, ke.privateKey.PrivateKey)
	ke.g3 = &bn256.GT{}
	g3, err := bn256.ScalarMultGT(ke.g2, ke.r.Bytes(orderNat))
	if err != nil {
		return nil, nil, err
	}
	ke.g3 = g3
	// step 6, verify signature
	if len(sB) > 0 {
		signature := ke.sign(false, 0x82)
		if subtle.ConstantTimeCompare(signature, sB) != 1 {
			return nil, nil, errors.New("sm9: invalid responder's signature")
		}
	}
	key, err := ke.generateSharedKey(false)
	if err != nil {
		return nil, nil, err
	}
	if !ke.genSignature {
		return key, nil, nil
	}
	return key, ke.sign(false, 0x83), nil
}

func (ke *KeyExchange) ConfirmInitiator(s1 []byte) ([]byte, error) {
	if s1 != nil {
		buffer := ke.sign(true, 0x83)
		if subtle.ConstantTimeCompare(buffer, s1) != 1 {
			return nil, errors.New("sm9: invalid initiator's signature")
		}
	}
	return ke.generateSharedKey(true)
}
