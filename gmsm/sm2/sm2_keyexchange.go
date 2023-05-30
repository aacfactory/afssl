package sm2

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/sm3"
)

// KeyExchange
// Usage:
// 1. initiator create key exchanging
// 1.1. initiator, err := sm2.NewKeyExchange(initiatorPRI, responderPUB, initiatorUID, responderUID, kenLen, true)
// 2.1. rA, rAErr := initiator.Init(rand.Reader)
// 2.3. send rA to responder
// 2. responder create key exchanging
// 2.1. responder, err := sm2.NewKeyExchange(responderPRI, initiatorPUB, responderUID, initiatorUID, kenLen, true)
// 2.2. rB, s2, rBErr := responder.Respond(rand.Reader, rA)
// 2.3. send rB and s2 to initiator
// 3. initiator confirm
// 3.1 ss, s1, err := initiator.ConfirmResponder(rB, s2)
// 3.2 initiator.Destroy()
// 3.3 send s1 to responder
// 4. responder confirm
// 4.1 ss, err := responder.ConfirmInitiator(s1)
// 4.2 responder.Destroy()
type KeyExchange struct {
	genSignature bool
	keyLength    int
	privateKey   *PrivateKey
	z            []byte
	peerPub      *ecdsa.PublicKey
	peerZ        []byte
	r            *big.Int
	secret       *ecdsa.PublicKey
	peerSecret   *ecdsa.PublicKey
	w2           *big.Int
	w2Minus1     *big.Int
	v            *ecdsa.PublicKey
}

func destroyBigInt(n *big.Int) {
	if n != nil {
		n.SetInt64(0)
	}
}

func destroyPublicKey(pub *ecdsa.PublicKey) {
	if pub != nil {
		destroyBigInt(pub.X)
		destroyBigInt(pub.Y)
	}
}

func destroyBytes(bytes []byte) {
	for v := range bytes {
		bytes[v] = 0
	}
}

func (ke *KeyExchange) Destroy() {
	destroyBytes(ke.z)
	destroyBytes(ke.peerZ)
	destroyBigInt(ke.r)
	destroyPublicKey(ke.v)
}

func NewKeyExchange(priv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int, genSignature bool) (ke *KeyExchange, err error) {
	ke = &KeyExchange{}
	ke.genSignature = genSignature

	ke.keyLength = keyLen
	ke.privateKey = priv

	one := big.NewInt(1)
	w := (priv.Params().N.BitLen()+1)/2 - 1

	ke.w2 = (&big.Int{}).Lsh(one, uint(w))
	ke.w2Minus1 = (&big.Int{}).Sub(ke.w2, one)

	if len(uid) == 0 {
		uid = defaultUID
	}
	ke.z, err = CalculateZA(&ke.privateKey.PublicKey, uid)
	if err != nil {
		return nil, err
	}

	err = ke.SetPeerParameters(peerPub, peerUID)
	if err != nil {
		return nil, err
	}

	ke.secret = &ecdsa.PublicKey{}
	ke.secret.Curve = priv.PublicKey.Curve

	ke.v = &ecdsa.PublicKey{}
	ke.v.Curve = priv.PublicKey.Curve

	return
}

func (ke *KeyExchange) SetPeerParameters(peerPub *ecdsa.PublicKey, peerUID []byte) error {
	if peerPub == nil {
		return nil
	}
	if len(peerUID) == 0 {
		peerUID = defaultUID
	}
	if ke.peerPub != nil {
		return errors.New("sm2: 'peerPub' already exists, please do not set it")
	}

	if peerPub.Curve != ke.privateKey.Curve {
		return errors.New("sm2: peer public key is not expected/supported")
	}

	var err error
	ke.peerPub = peerPub
	ke.peerZ, err = CalculateZA(ke.peerPub, peerUID)
	if err != nil {
		return err
	}
	ke.peerSecret = &ecdsa.PublicKey{}
	ke.peerSecret.Curve = peerPub.Curve
	return nil
}

func initKeyExchange(ke *KeyExchange, r *big.Int) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r
}

func (ke *KeyExchange) Init(rand io.Reader) (*ecdsa.PublicKey, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, r)
	return ke.secret, nil
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
	var buffer []byte
	hash := sm3.New()
	hash.Write(toBytes(ke.privateKey, ke.v.X))
	if isResponder {
		hash.Write(ke.peerZ)
		hash.Write(ke.z)
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
	} else {
		hash.Write(ke.z)
		hash.Write(ke.peerZ)
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
	}
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{prefix})
	hash.Write(toBytes(ke.privateKey, ke.v.Y))
	hash.Write(buffer)
	return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) ([]byte, error) {
	var buffer []byte
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.X)...)
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.Y)...)
	if isResponder {
		buffer = append(buffer, ke.peerZ...)
		buffer = append(buffer, ke.z...)
	} else {
		buffer = append(buffer, ke.z...)
		buffer = append(buffer, ke.peerZ...)
	}
	return kdf.Kdf(sm3.New(), buffer, ke.keyLength), nil
}

func (ke *KeyExchange) avf(x *big.Int) *big.Int {
	t := (&big.Int{}).And(ke.w2Minus1, x)
	t.Add(ke.w2, t)
	return t
}

func (ke *KeyExchange) mqv() {
	t := ke.avf(ke.secret.X)

	t.Mul(t, ke.r)
	t.Add(t, ke.privateKey.D)
	t.Mod(t, ke.privateKey.Params().N)

	x1 := ke.avf(ke.peerSecret.X)
	x, y := ke.privateKey.ScalarMult(ke.peerSecret.X, ke.peerSecret.Y, x1.Bytes())
	x, y = ke.privateKey.Add(ke.peerPub.X, ke.peerPub.Y, x, y)

	ke.v.X, ke.v.Y = ke.privateKey.ScalarMult(x, y, t.Bytes())
}

func respondKeyExchange(ke *KeyExchange, rA *ecdsa.PublicKey, r *big.Int) (*ecdsa.PublicKey, []byte, error) {
	if ke.peerPub == nil {
		return nil, nil, errors.New("sm2: no peer public key given")
	}
	if !ke.privateKey.IsOnCurve(rA.X, rA.Y) {
		return nil, nil, errors.New("sm2: invalid initiator's ephemeral public key")
	}
	ke.peerSecret = rA
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r

	ke.mqv()
	if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
		return nil, nil, errors.New("sm2: key exchange failed, V is infinity point")
	}

	if !ke.genSignature {
		return ke.secret, nil, nil
	}

	return ke.secret, ke.sign(true, 0x02), nil
}

func (ke *KeyExchange) Respond(rand io.Reader, rA *ecdsa.PublicKey) (*ecdsa.PublicKey, []byte, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, nil, err
	}
	return respondKeyExchange(ke, rA, r)
}

func (ke *KeyExchange) ConfirmResponder(rB *ecdsa.PublicKey, sB []byte) ([]byte, []byte, error) {
	if ke.peerPub == nil {
		return nil, nil, errors.New("sm2: no peer public key given")
	}
	if !ke.privateKey.IsOnCurve(rB.X, rB.Y) {
		return nil, nil, errors.New("sm2: invalid responder's ephemeral public key")
	}
	ke.peerSecret = rB

	ke.mqv()
	if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
		return nil, nil, errors.New("sm2: key exchange failed, U is infinity point")
	}

	if len(sB) > 0 {
		buffer := ke.sign(false, 0x02)
		if subtle.ConstantTimeCompare(buffer, sB) != 1 {
			return nil, nil, errors.New("sm2: invalid responder's signature")
		}
	}
	key, err := ke.generateSharedKey(false)
	if err != nil {
		return nil, nil, err
	}

	if !ke.genSignature {
		return key, nil, nil
	}
	return key, ke.sign(false, 0x03), nil
}

func (ke *KeyExchange) ConfirmInitiator(s1 []byte) ([]byte, error) {
	if s1 != nil {
		buffer := ke.sign(true, 0x03)
		if subtle.ConstantTimeCompare(buffer, s1) != 1 {
			return nil, errors.New("sm2: invalid initiator's signature")
		}
	}
	return ke.generateSharedKey(true)
}
