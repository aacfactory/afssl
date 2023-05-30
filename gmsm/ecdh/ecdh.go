package ecdh

import (
	"crypto"
	"crypto/subtle"
	"hash"
	"io"
	"sync"

	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/sm3"
)

type Curve interface {
	GenerateKey(rand io.Reader) (*PrivateKey, error)
	NewPrivateKey(key []byte) (*PrivateKey, error)
	NewPublicKey(key []byte) (*PublicKey, error)
	ecdh(local *PrivateKey, remote *PublicKey) ([]byte, error)
	sm2mqv(sLocal, eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error)
	sm2za(md hash.Hash, pub *PublicKey, uid []byte) ([]byte, error)
	privateKeyToPublicKey(*PrivateKey) *PublicKey
}

type PublicKey struct {
	curve     Curve
	publicKey []byte
}

func (k *PublicKey) Bytes() []byte {
	var buf [133]byte
	return append(buf[:0], k.publicKey...)
}

func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return k.curve == xx.curve &&
		subtle.ConstantTimeCompare(k.publicKey, xx.publicKey) == 1
}

func (k *PublicKey) Curve() Curve {
	return k.curve
}

func (k *PublicKey) SM2ZA(md hash.Hash, uid []byte) ([]byte, error) {
	return k.curve.sm2za(md, k, uid)
}

func (uv *PublicKey) SM2SharedKey(isResponder bool, kenLen int, sPub, sRemote *PublicKey, uid []byte, remoteUID []byte) ([]byte, error) {
	var buffer [128]byte
	copy(buffer[:], uv.publicKey[1:])
	peerZ, err := sRemote.SM2ZA(sm3.New(), remoteUID)
	if err != nil {
		return nil, err
	}
	z, err := sPub.SM2ZA(sm3.New(), uid)
	if err != nil {
		return nil, err
	}
	if isResponder {
		copy(buffer[64:], peerZ)
		copy(buffer[96:], z)
	} else {
		copy(buffer[64:], z)
		copy(buffer[96:], peerZ)
	}

	return kdf.Kdf(sm3.New(), buffer[:], kenLen), nil
}

type PrivateKey struct {
	curve         Curve
	privateKey    []byte
	publicKey     *PublicKey
	publicKeyOnce sync.Once
}

func (k *PrivateKey) ECDH(remote *PublicKey) ([]byte, error) {
	return k.curve.ecdh(k, remote)
}

func (k *PrivateKey) SM2MQV(eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error) {
	return k.curve.sm2mqv(k, eLocal, sRemote, eRemote)
}

func (k *PrivateKey) Bytes() []byte {
	var buf [66]byte
	return append(buf[:0], k.privateKey...)
}

func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return k.curve == xx.curve &&
		subtle.ConstantTimeCompare(k.privateKey, xx.privateKey) == 1
}

func (k *PrivateKey) Curve() Curve {
	return k.curve
}

func (k *PrivateKey) PublicKey() *PublicKey {
	k.publicKeyOnce.Do(func() {
		k.publicKey = k.curve.privateKeyToPublicKey(k)
	})
	return k.publicKey
}

func (k *PrivateKey) Public() crypto.PublicKey {
	return k.PublicKey()
}
