package ecdh

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/bits"

	"github.com/aacfactory/afssl/gmsm/internal/randutil"
	_sm2ec "github.com/aacfactory/afssl/gmsm/internal/sm2ec"
)

type sm2Curve struct {
	name        string
	newPoint    func() *_sm2ec.SM2P256Point
	scalarOrder []byte
	constantA   []byte
	constantB   []byte
	generator   []byte
}

func (c *sm2Curve) String() string {
	return c.name
}

func (c *sm2Curve) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	key := make([]byte, len(c.scalarOrder))
	randutil.MaybeReadByte(rand)

	for {
		if _, err := io.ReadFull(rand, key); err != nil {
			return nil, err
		}

		key[1] ^= 0x42

		k, err := c.NewPrivateKey(key)
		if err == errInvalidPrivateKey {
			continue
		}
		return k, err
	}
}

func (c *sm2Curve) NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != len(c.scalarOrder) {
		return nil, errors.New("ecdh: invalid private key size")
	}
	if subtle.ConstantTimeCompare(key, nil) == 1 || !isLess(key, c.scalarOrder) {
		return nil, errInvalidPrivateKey
	}
	return &PrivateKey{
		curve:      c,
		privateKey: append([]byte{}, key...),
	}, nil
}

func (c *sm2Curve) privateKeyToPublicKey(key *PrivateKey) *PublicKey {
	if key.curve != c {
		panic("ecdh: internal error: converting the wrong key type")
	}
	p, err := c.newPoint().ScalarBaseMult(key.privateKey)
	if err != nil {
		panic("ecdh: internal error: sm2ec ScalarBaseMult failed for a fixed-size input")
	}
	publicKey := p.Bytes()
	if len(publicKey) == 1 {
		// The encoding of the identity is a single 0x00 byte. This is
		// unreachable because the only scalar that generates the identity is
		// zero, which is rejected by NewPrivateKey.
		panic("ecdh: internal error: sm2ec ScalarBaseMult returned the identity")
	}
	return &PublicKey{
		curve:     key.curve,
		publicKey: publicKey,
	}
}

func (c *sm2Curve) NewPublicKey(key []byte) (*PublicKey, error) {
	if len(key) == 0 || key[0] != 4 {
		return nil, errors.New("ecdh: invalid public key")
	}
	if _, err := c.newPoint().SetBytes(key); err != nil {
		return nil, err
	}

	return &PublicKey{
		curve:     c,
		publicKey: append([]byte{}, key...),
	}, nil
}

func (c *sm2Curve) ecdh(local *PrivateKey, remote *PublicKey) ([]byte, error) {
	p, err := c.newPoint().SetBytes(remote.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := p.ScalarMult(p, local.privateKey); err != nil {
		return nil, err
	}
	return p.BytesX()
}

func (c *sm2Curve) sm2avf(secret *PublicKey) []byte {
	bytes := secret.publicKey[1:33]
	var result [32]byte
	copy(result[16:], bytes[16:])
	result[16] = (result[16] & 0x7f) | 0x80

	return result[:]
}

func (c *sm2Curve) sm2mqv(sLocal, eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error) {
	x2 := c.sm2avf(eLocal.PublicKey())
	t, err := _sm2ec.ImplicitSig(sLocal.privateKey, eLocal.privateKey, x2)
	if err != nil {
		return nil, err
	}

	x1 := c.sm2avf(eRemote)
	p2, err := c.newPoint().SetBytes(eRemote.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := p2.ScalarMult(p2, x1); err != nil {
		return nil, err
	}
	p1, err := c.newPoint().SetBytes(sRemote.publicKey)
	if err != nil {
		return nil, err
	}
	p2.Add(p1, p2)

	if _, err := p2.ScalarMult(p2, t); err != nil {
		return nil, err
	}
	return c.NewPublicKey(p2.Bytes())
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

func (c *sm2Curve) sm2za(md hash.Hash, pub *PublicKey, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("ecdh: the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	md.Write(c.constantA)
	md.Write(c.constantB)
	md.Write(c.generator)
	md.Write(pub.publicKey[1:])

	return md.Sum(nil), nil
}

func P256() Curve { return sm2P256 }

var sm2P256 = &sm2Curve{
	name:        "sm2p256v1",
	newPoint:    _sm2ec.NewSM2P256Point,
	scalarOrder: sm2P256Order,
	generator:   sm2Generator,
	constantA:   sm2ConstantA,
	constantB:   sm2ConstantB,
}

var sm2P256Order = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
	0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23}
var sm2Generator = []byte{
	0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
	0x5f, 0x99, 0x4, 0x46, 0x6a, 0x39, 0xc9, 0x94,
	0x8f, 0xe3, 0xb, 0xbf, 0xf2, 0x66, 0xb, 0xe1,
	0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
	0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
	0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
	0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
	0x2, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0}
var sm2ConstantA = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc}
var sm2ConstantB = []byte{
	0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
	0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
	0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
	0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93}

func isLess(a, b []byte) bool {
	if len(a) != len(b) {
		panic("ecdh: internal error: mismatched isLess inputs")
	}

	if len(a) > 72 {
		panic("ecdh: internal error: isLess input too large")
	}
	bufA, bufB := make([]byte, 72), make([]byte, 72)
	for i := range a {
		bufA[i], bufB[i] = a[len(a)-i-1], b[len(b)-i-1]
	}

	var borrow uint64
	for i := 0; i < len(bufA); i += 8 {
		limbA, limbB := binary.LittleEndian.Uint64(bufA[i:]), binary.LittleEndian.Uint64(bufB[i:])
		_, borrow = bits.Sub64(limbA, limbB, borrow)
	}

	return borrow == 1
}

var errInvalidPrivateKey = errors.New("ecdh: invalid private key")
