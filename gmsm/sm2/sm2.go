package sm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/ecdh"
	"io"
	"math/big"
	"sync"

	"github.com/aacfactory/afssl/gmsm/internal/bigmod"
	"github.com/aacfactory/afssl/gmsm/internal/randutil"
	_sm2ec "github.com/aacfactory/afssl/gmsm/internal/sm2ec"
	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/sm2/sm2ec"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	uncompressed byte = 0x04
	compressed02 byte = 0x02
	compressed03 byte = compressed02 | 0x01
	hybrid06     byte = 0x06
	hybrid07     byte = hybrid06 | 0x01
)

type PrivateKey struct {
	ecdsa.PrivateKey
}

type pointMarshalMode byte

const (
	MarshalUncompressed pointMarshalMode = iota
	MarshalCompressed
	MarshalHybrid
)

type ciphertextSplicingOrder byte

const (
	C1C3C2 ciphertextSplicingOrder = iota
	C1C2C3
)

type ciphertextEncoding byte

const (
	encodingPlain ciphertextEncoding = iota
	encodingAsn1
)

func NewPlainEncryptorOpts(marhsalMode pointMarshalMode, splicingOrder ciphertextSplicingOrder) *EncryptorOpts {
	return &EncryptorOpts{encodingPlain, marhsalMode, splicingOrder}
}

type EncryptorOpts struct {
	ciphertextEncoding      ciphertextEncoding
	pointMarshalMode        pointMarshalMode
	ciphertextSplicingOrder ciphertextSplicingOrder
}

func NewPlainDecryptorOpts(splicingOrder ciphertextSplicingOrder) *DecryptorOpts {
	return &DecryptorOpts{encodingPlain, splicingOrder}
}

type DecryptorOpts struct {
	ciphertextEncoding      ciphertextEncoding
	cipherTextSplicingOrder ciphertextSplicingOrder
}

func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	result := make([]byte, byteLen)
	value.FillBytes(result)
	return result
}

var defaultEncryptorOpts = &EncryptorOpts{encodingPlain, MarshalUncompressed, C1C3C2}

var ASN1EncryptorOpts = &EncryptorOpts{encodingAsn1, MarshalUncompressed, C1C3C2}

var ASN1DecryptorOpts = &DecryptorOpts{encodingAsn1, C1C3C2}

var directSigning crypto.Hash = 0

type Signer interface {
	SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error)
}

type SignerOption struct {
	uid         []byte
	forceGMSign bool
}

func NewSignerOption(forceGMSign bool, uid []byte) *SignerOption {
	opt := &SignerOption{
		uid:         uid,
		forceGMSign: forceGMSign,
	}
	if forceGMSign && len(uid) == 0 {
		opt.uid = defaultUID
	}
	return opt
}

var DefaultSignerOpts = NewSignerOption(true, nil)

func (*SignerOption) HashFunc() crypto.Hash {
	return directSigning
}

func (pri *PrivateKey) FromECPrivateKey(key *ecdsa.PrivateKey) (*PrivateKey, error) {
	if key.Curve != sm2ec.P256() {
		return nil, errors.New("sm2: it's NOT a sm2 curve private key")
	}
	pri.PrivateKey = *key
	return pri, nil
}

func (pri *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return pri.PublicKey.Equal(&xx.PublicKey) && bigIntEqual(pri.D, xx.D)
}

func bigIntEqual(a, b *big.Int) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

func (pri *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignASN1(rand, pri, digest, opts)
}

// SignWithSM2 signs uid, msg with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// Deprecated: please use Sign method directly.
func (pri *PrivateKey) SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error) {
	return pri.Sign(rand, msg, NewSignerOption(true, uid))
}

func (pri *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	var sm2Opts *DecryptorOpts
	sm2Opts, _ = opts.(*DecryptorOpts)
	return decrypt(pri, msg, sm2Opts)
}

const maxRetryLimit = 100

var (
	errCiphertextTooShort = errors.New("sm2: ciphertext too short")
)

func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	return Encrypt(random, pub, msg, ASN1EncryptorOpts)
}

func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncryptorOpts) ([]byte, error) {
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("sm2: public key point is the infinity")
	}
	if len(msg) == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = defaultEncryptorOpts
	}
	switch pub.Curve.Params() {
	case P256().Params():
		return encryptSM2EC(p256(), pub, random, msg, opts)
	default:
		return encryptLegacy(random, pub, msg, opts)
	}
}

func encryptSM2EC(c *sm2Curve, pub *ecdsa.PublicKey, random io.Reader, msg []byte, opts *EncryptorOpts) ([]byte, error) {
	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	var retryCount int = 0
	for {
		k, C1, err := randomPoint(c, random)
		if err != nil {
			return nil, err
		}
		C2, err := Q.ScalarMult(Q, k.Bytes(c.N))
		if err != nil {
			return nil, err
		}
		C2Bytes := C2.Bytes()[1:]
		c2 := kdf.Kdf(sm3.New(), C2Bytes, len(msg))
		if subtle.ConstantTimeCompare(c2, nil) == 1 {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
			}
			continue
		}
		subtle.XORBytes(c2, msg, c2)

		md := sm3.New()
		md.Write(C2Bytes[:len(C2Bytes)/2])
		md.Write(msg)
		md.Write(C2Bytes[len(C2Bytes)/2:])
		c3 := md.Sum(nil)

		if opts.ciphertextEncoding == encodingPlain {
			return encodingCiphertext(opts, C1, c2, c3)
		}
		return encodingCiphertextASN1(C1, c2, c3)
	}
}

func encodingCiphertext(opts *EncryptorOpts, C1 *_sm2ec.SM2P256Point, c2, c3 []byte) ([]byte, error) {
	var c1 []byte
	switch opts.pointMarshalMode {
	case MarshalCompressed:
		c1 = C1.BytesCompressed()
	default:
		c1 = C1.Bytes()
	}

	if opts.ciphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	return append(append(c1, c2...), c3...), nil
}

func encodingCiphertextASN1(C1 *_sm2ec.SM2P256Point, c2, c3 []byte) ([]byte, error) {
	c1 := C1.Bytes()
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, c1[1:len(c1)/2+1])
		addASN1IntBytes(b, c1[len(c1)/2+1:])
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := p256()
	k, Q, err := randomPoint(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c.curve
	priv.D = new(big.Int).SetBytes(k.Bytes(c.N))
	priv.PublicKey.X, priv.PublicKey.Y, err = c.pointToAffine(Q)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, nil)
}

var ErrDecryption = errors.New("sm2: decryption error")

func decrypt(priv *PrivateKey, ciphertext []byte, opts *DecryptorOpts) ([]byte, error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errCiphertextTooShort
	}
	switch priv.Curve.Params() {
	case P256().Params():
		return decryptSM2EC(p256(), priv, ciphertext, opts)
	default:
		return decryptLegacy(priv, ciphertext, opts)
	}
}

func decryptSM2EC(c *sm2Curve, priv *PrivateKey, ciphertext []byte, opts *DecryptorOpts) ([]byte, error) {
	C1, c2, c3, err := parseCiphertext(c, ciphertext, opts)
	if err != nil {
		return nil, ErrDecryption
	}
	d, err := bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, ErrDecryption
	}

	C2, err := C1.ScalarMult(C1, d.Bytes(c.N))
	if err != nil {
		return nil, ErrDecryption
	}
	C2Bytes := C2.Bytes()[1:]
	msgLen := len(c2)
	msg := kdf.Kdf(sm3.New(), C2Bytes, msgLen)
	if subtle.ConstantTimeCompare(c2, nil) == 1 {
		return nil, ErrDecryption
	}

	subtle.XORBytes(msg, c2, msg)

	md := sm3.New()
	md.Write(C2Bytes[:len(C2Bytes)/2])
	md.Write(msg)
	md.Write(C2Bytes[len(C2Bytes)/2:])
	u := md.Sum(nil)

	if subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

func parseCiphertext(c *sm2Curve, ciphertext []byte, opts *DecryptorOpts) (*_sm2ec.SM2P256Point, []byte, []byte, error) {
	bitSize := c.curve.Params().BitSize
	byteLen := (bitSize + 7) / 8
	splicingOrder := C1C3C2
	if opts != nil {
		splicingOrder = opts.cipherTextSplicingOrder
	}

	b := ciphertext[0]
	switch b {
	case uncompressed:
		if len(ciphertext) <= 1+2*byteLen+sm3.Size {
			return nil, nil, nil, errCiphertextTooShort
		}
		C1, err := c.newPoint().SetBytes(ciphertext[:1+2*byteLen])
		if err != nil {
			return nil, nil, nil, err
		}
		c2, c3 := parseCiphertextC2C3(ciphertext[1+2*byteLen:], splicingOrder)
		return C1, c2, c3, nil
	case compressed02, compressed03:
		C1, err := c.newPoint().SetBytes(ciphertext[:1+byteLen])
		if err != nil {
			return nil, nil, nil, err
		}
		c2, c3 := parseCiphertextC2C3(ciphertext[1+byteLen:], splicingOrder)
		return C1, c2, c3, nil
	case byte(0x30):
		return parseCiphertextASN1(c, ciphertext)
	default:
		return nil, nil, nil, errors.New("sm2: invalid/unsupport ciphertext format")
	}
}

func parseCiphertextC2C3(ciphertext []byte, order ciphertextSplicingOrder) ([]byte, []byte) {
	if order == C1C3C2 {
		return ciphertext[sm3.Size:], ciphertext[:sm3.Size]
	}
	return ciphertext[:len(ciphertext)-sm3.Size], ciphertext[len(ciphertext)-sm3.Size:]
}

func unmarshalASN1Ciphertext(ciphertext []byte) (*big.Int, *big.Int, []byte, []byte, error) {
	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, nil, nil, nil, errors.New("sm2: invalid asn1 format ciphertext")
	}
	return x1, y1, c2, c3, nil
}

func parseCiphertextASN1(c *sm2Curve, ciphertext []byte) (*_sm2ec.SM2P256Point, []byte, []byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	C1, err := c.pointFromAffine(x1, y1)
	if err != nil {
		return nil, nil, nil, err
	}
	return C1, c2, c3, nil
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("sm2: the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md := sm3.New()
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	a := new(big.Int).Sub(pub.Params().P, big.NewInt(3))
	md.Write(toBytes(pub.Curve, a))
	md.Write(toBytes(pub.Curve, pub.Params().B))
	md.Write(toBytes(pub.Curve, pub.Params().Gx))
	md.Write(toBytes(pub.Curve, pub.Params().Gy))
	md.Write(toBytes(pub.Curve, pub.X))
	md.Write(toBytes(pub.Curve, pub.Y))
	return md.Sum(nil), nil
}

func calculateSM2Hash(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := CalculateZA(pub, uid)
	if err != nil {
		return nil, err
	}
	md := sm3.New()
	md.Write(za)
	md.Write(data)
	return md.Sum(nil), nil
}

func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	if sm2Opts, ok := opts.(*SignerOption); ok && sm2Opts.forceGMSign {
		newHash, err := calculateSM2Hash(&priv.PublicKey, hash, sm2Opts.uid)
		if err != nil {
			return nil, err
		}
		hash = newHash
	}

	randutil.MaybeReadByte(rand)
	csprng, err := mixedCSPRNG(rand, &priv.PrivateKey, hash)
	if err != nil {
		return nil, err
	}

	switch priv.Curve.Params() {
	case P256().Params():
		return signSM2EC(p256(), priv, csprng, hash)
	default:
		return signLegacy(priv, csprng, hash)
	}
}

func signSM2EC(c *sm2Curve, priv *PrivateKey, csprng io.Reader, hash []byte) (sig []byte, err error) {
	e := bigmod.NewNat()
	hashToNat(c, e, hash)
	var (
		k, r, s, dp1Inv, oneNat *bigmod.Nat
		R                       *_sm2ec.SM2P256Point
	)

	oneNat, err = bigmod.NewNat().SetBytes(one.Bytes(), c.N)
	if err != nil {
		return nil, err
	}
	dp1Inv, err = bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, err
	}
	dp1Inv.Add(oneNat, c.N)
	dp1Bytes, err := _sm2ec.P256OrdInverse(dp1Inv.Bytes(c.N))
	if err != nil {
		return nil, err
	}
	dp1Inv, err = bigmod.NewNat().SetBytes(dp1Bytes, c.N)
	if err != nil {
		panic("sm2: internal error: P256OrdInverse produced an invalid value")
	}

	for {
		for {
			k, R, err = randomPoint(c, csprng)
			if err != nil {
				return nil, err
			}
			Rx, err := R.BytesX()
			if err != nil {
				return nil, err
			}
			r, err = bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
			if err != nil {
				return nil, err
			}
			r.Add(e, c.N) // r = (Rx + e) mod N
			if r.IsZero() == 0 {
				t := bigmod.NewNat().Set(k)
				t.Add(r, c.N)
				if t.IsZero() == 0 { // if (r + k) != N then ok
					break
				}
			}
		}
		s, err = bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
		if err != nil {
			return nil, err
		}
		s.Mul(r, c.N)
		k.Sub(s, c.N)
		k.Mul(dp1Inv, c.N)
		if k.IsZero() == 0 {
			break
		}
	}

	return encodeSignature(r.Bytes(c.N), k.Bytes(c.N))
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	switch pub.Curve.Params() {
	case P256().Params():
		return verifySM2EC(p256(), pub, hash, sig)
	default:
		return verifyLegacy(pub, hash, sig)
	}
}

func verifySM2EC(c *sm2Curve, pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}

	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return false
	}

	r, err := bigmod.NewNat().SetBytes(rBytes, c.N)
	if err != nil || r.IsZero() == 1 {
		return false
	}
	s, err := bigmod.NewNat().SetBytes(sBytes, c.N)
	if err != nil || s.IsZero() == 1 {
		return false
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	t := bigmod.NewNat().Set(r)
	t.Add(s, c.N)
	if t.IsZero() == 1 {
		return false
	}

	p1, err := c.newPoint().ScalarBaseMult(s.Bytes(c.N))
	if err != nil {
		return false
	}
	p2, err := Q.ScalarMult(Q, t.Bytes(c.N))
	if err != nil {
		return false
	}

	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return false
	}

	v, err := bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return false
	}

	v.Add(e, c.N)
	return v.Equal(r) == 1
}

func VerifyASN1WithSM2(pub *ecdsa.PublicKey, uid, msg, sig []byte) bool {
	digest, err := calculateSM2Hash(pub, msg, uid)
	if err != nil {
		return false
	}
	return VerifyASN1(pub, digest, sig)
}

func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}

func hashToNat(c *sm2Curve, e *bigmod.Nat, hash []byte) {
	if size := c.N.Size(); len(hash) > size {
		hash = hash[:size]
		if excess := len(hash)*8 - c.N.BitLen(); excess > 0 {
			hash = append([]byte{}, hash...)
			for i := len(hash) - 1; i >= 0; i-- {
				hash[i] >>= excess
				if i > 0 {
					hash[i] |= hash[i-1] << (8 - excess)
				}
			}
		}
	}
	_, err := e.SetOverflowingBytes(hash, c.N)
	if err != nil {
		panic("sm2: internal error: truncated hash is too long")
	}
}

func mixedCSPRNG(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (io.Reader, error) {
	entropy := make([]byte, 32)
	if _, err := io.ReadFull(rand, entropy); err != nil {
		return nil, err
	}

	md := sha512.New()
	md.Write(priv.D.Bytes())
	md.Write(entropy)
	md.Write(hash)
	key := md.Sum(nil)[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	const aesIV = "IV for ECDSA CTR"
	return &cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}, nil
}

type zr struct{}

var zeroReader = &zr{}

func (zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

func IsPublicKey(publicKey interface{}) bool {
	pub, ok := publicKey.(*ecdsa.PublicKey)
	return ok && pub.Curve == sm2ec.P256()
}

func P256() elliptic.Curve {
	return sm2ec.P256()
}

func PublicKeyToECDH(k *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("sm2: unsupported curve by ecdh")
	}
	if !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, errors.New("sm2: invalid public key")
	}
	return c.NewPublicKey(elliptic.Marshal(k.Curve, k.X, k.Y))
}

func (pri *PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	c := curveToECDH(pri.Curve)
	if c == nil {
		return nil, errors.New("sm2: unsupported curve by ecdh")
	}
	size := (pri.Curve.Params().N.BitLen() + 7) / 8
	if pri.D.BitLen() > size*8 {
		return nil, errors.New("sm2: invalid private key")
	}
	return c.NewPrivateKey(pri.D.FillBytes(make([]byte, size)))
}

func curveToECDH(c elliptic.Curve) ecdh.Curve {
	switch c {
	case sm2ec.P256():
		return ecdh.P256()
	default:
		return nil
	}
}

func randomPoint(c *sm2Curve, rand io.Reader) (k *bigmod.Nat, p *_sm2ec.SM2P256Point, err error) {
	k = bigmod.NewNat()
	for {
		b := make([]byte, c.N.Size())
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}

		if excess := len(b)*8 - c.N.BitLen(); excess > 0 {
			if excess != 0 {
				panic("sm2: internal error: unexpectedly masking off bits")
			}
			b[0] >>= excess
		}

		if _, err = k.SetBytes(b, c.N); err == nil && k.IsZero() == 0 {
			break
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}

	p, err = c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	return
}

var testingOnlyRejectionSamplingLooped func()

type sm2Curve struct {
	newPoint func() *_sm2ec.SM2P256Point
	curve    elliptic.Curve
	N        *bigmod.Modulus
	nMinus2  []byte
}

func (curve *sm2Curve) pointFromAffine(x, y *big.Int) (p *_sm2ec.SM2P256Point, err error) {
	bitSize := curve.curve.Params().BitSize
	if x.Sign() < 0 || y.Sign() < 0 {
		return p, errors.New("negative coordinate")
	}
	if x.BitLen() > bitSize || y.BitLen() > bitSize {
		return p, errors.New("overflowing coordinate")
	}
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return curve.newPoint().SetBytes(buf)
}

func (curve *sm2Curve) pointToAffine(p *_sm2ec.SM2P256Point) (x, y *big.Int, err error) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("sm2: public key point is the infinity")
	}
	byteLen := (curve.curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y, nil
}

var p256Once sync.Once
var _p256 *sm2Curve

func p256() *sm2Curve {
	p256Once.Do(func() {
		_p256 = &sm2Curve{
			newPoint: func() *_sm2ec.SM2P256Point { return _sm2ec.NewSM2P256Point() },
		}
		precomputeParams(_p256, P256())
	})
	return _p256
}

func precomputeParams(c *sm2Curve, curve elliptic.Curve) {
	params := curve.Params()
	c.curve = curve
	c.N = bigmod.NewModulusFromBig(params.N)
	c.nMinus2 = new(big.Int).Sub(params.N, big.NewInt(2)).Bytes()
}
