package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/sm3"
)

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

func UnmarshalKeyExchange(p []byte) (ke *KeyExchange, err error) {
	pLen := len(p)
	if pLen == 0 {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	dst := make([]byte, base64.StdEncoding.DecodedLen(pLen))
	n, decodeErr := base64.StdEncoding.Decode(dst, p)
	if decodeErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	p = dst[0:n]
	if len(p) < 86 {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	ke = &KeyExchange{}
	// genSignature
	ke.genSignature = binary.BigEndian.Uint16(p[0:2]) == 1
	p = p[2:]
	// keyLength
	if len(p) < 4 {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	ke.keyLength = int(binary.BigEndian.Uint32(p[0:4]))
	p = p[4:]
	// privateKey
	privateKeyDer, privateKeyLen, decodePrivateKeyErr := decodeLengthFieldBasedFrame(p)
	if decodePrivateKeyErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if privateKeyLen > 0 {
		ke.privateKey, err = UnmarshalPrivateKey(privateKeyDer)
		if err != nil {
			err = errors.New("sm2: unmarshal key exchange failed")
			return
		}
		if err != nil {
			err = errors.New("sm2: unmarshal key exchange failed")
			return
		}
	}
	p = p[8+privateKeyLen:]
	// z
	z, zLen, decodeZ := decodeLengthFieldBasedFrame(p)
	if decodeZ != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if zLen > 0 {
		ke.z = z
	}
	p = p[8+zLen:]
	// peerPub
	peerPubKeyDer, peerPubKeyLen, decodePeerPubKeyErr := decodeLengthFieldBasedFrame(p)
	if decodePeerPubKeyErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if peerPubKeyLen > 0 {
		ke.peerPub, err = UnmarshalPublicKey(peerPubKeyDer)
		if err != nil {
			err = errors.New("sm2: unmarshal key exchange failed")
			return
		}
	}
	p = p[8+peerPubKeyLen:]
	// peerZ
	peerZ, peerZLen, decodePeerZErr := decodeLengthFieldBasedFrame(p)
	if decodePeerZErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if peerZLen > 0 {
		ke.peerZ = peerZ
	}
	p = p[8+peerZLen:]
	// r
	ke.r = new(big.Int)
	r, rLen, decodeRErr := decodeLengthFieldBasedFrame(p)
	if decodeRErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if rLen > 0 {
		ke.r = ke.r.SetBytes(r)
	}
	p = p[8+rLen:]
	// secret
	secretDer, secretLen, decodeSecretErr := decodeLengthFieldBasedFrame(p)
	if decodeSecretErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if secretLen > 0 {
		ke.secret, err = UnmarshalPublicKey(secretDer)
		if err != nil {
			err = errors.New("sm2: unmarshal key exchange failed")
			return
		}
	} else {
		ke.secret = &ecdsa.PublicKey{}
		ke.secret.Curve = ke.privateKey.PublicKey.Curve
	}
	p = p[8+secretLen:]
	// peerSecret
	secretSecretDer, secretSecretLen, decodeSecretSecretErr := decodeLengthFieldBasedFrame(p)
	if decodeSecretSecretErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if secretSecretLen > 0 {
		ke.peerSecret, err = UnmarshalPublicKey(secretSecretDer)
		if err != nil {
			err = errors.New("sm2: unmarshal key exchange failed")
			return
		}
	}
	p = p[8+secretSecretLen:]
	// w2
	ke.w2 = new(big.Int)
	w2, w2Len, decodeW2Err := decodeLengthFieldBasedFrame(p)
	if decodeW2Err != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if w2Len > 0 {
		ke.w2 = ke.w2.SetBytes(w2)
	}
	p = p[8+w2Len:]
	// w2Minus1
	ke.w2Minus1 = new(big.Int)
	w2Minus1, w2Minus1Len, decodeW2Minus1Err := decodeLengthFieldBasedFrame(p)
	if decodeW2Minus1Err != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if w2Minus1Len > 0 {
		ke.w2Minus1 = ke.w2Minus1.SetBytes(w2Minus1)
	}
	p = p[8+w2Minus1Len:]
	// v
	vDer, vLen, decodeVErr := decodeLengthFieldBasedFrame(p)
	if decodeVErr != nil {
		err = errors.New("sm2: unmarshal key exchange failed")
		return
	}
	if vLen > 0 {
		ke.v, err = UnmarshalPublicKey(vDer)
		if err != nil {
			err = errors.New("sm2: unmarshal key exchange failed")
			return
		}
	} else {
		ke.v = &ecdsa.PublicKey{}
		ke.v.Curve = ke.privateKey.PublicKey.Curve
	}
	return
}

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

func (ke *KeyExchange) Init(rand io.Reader) (*ecdsa.PublicKey, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, r)
	return ke.secret, nil
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

func (ke *KeyExchange) Destroy() {
	ke.z = nil
	ke.peerZ = nil
	if ke.r != nil {
		ke.r.SetInt64(0)
	}
	if ke.v != nil {
		if ke.v.X != nil {
			ke.v.X.SetInt64(0)
		}
		if ke.v.Y != nil {
			ke.v.Y.SetInt64(0)
		}
	}
}

func (ke *KeyExchange) Equal(x *KeyExchange) bool {
	if ke.genSignature != x.genSignature {
		return false
	}
	if ke.keyLength != x.keyLength {
		return false
	}
	if !ke.privateKey.Equal(x.privateKey) {
		return false
	}
	if bytes.Compare(ke.z, x.z) != 0 {
		return false
	}
	if !ke.peerPub.Equal(x.peerPub) {
		return false
	}
	if bytes.Compare(ke.peerZ, x.peerZ) != 0 {
		return false
	}
	if ke.r.Uint64() != x.r.Uint64() {
		return false
	}
	if !ke.secret.Equal(x.secret) {
		return false
	}
	if ke.w2.Uint64() != x.w2.Uint64() {
		return false
	}
	if ke.w2Minus1.Uint64() != x.w2Minus1.Uint64() {
		return false
	}
	return true
}

func (ke *KeyExchange) Marshal() (p []byte, err error) {
	p = make([]byte, 0, 8)
	// genSignature
	gsp := make([]byte, 2)
	if ke.genSignature {
		binary.BigEndian.PutUint16(gsp, 1)
	} else {
		binary.BigEndian.PutUint16(gsp, 0)
	}
	p = append(p, gsp...)
	// keyLength
	lkp := make([]byte, 4)
	binary.BigEndian.PutUint32(lkp, uint32(ke.keyLength))
	p = append(p, lkp...)
	// privateKey
	var priKeyDer []byte
	if ke.privateKey != nil && ke.privateKey.X != nil {
		priKeyDer, err = ke.privateKey.Marshal()
		if err != nil {
			err = errors.New("sm2: marshal key exchange failed")
			return
		}
	}
	p = append(p, encodeLengthFieldBasedFrame(priKeyDer)...)
	// z
	p = append(p, encodeLengthFieldBasedFrame(ke.z)...)
	// peerPub
	var peerPubDer []byte
	if ke.peerPub != nil && ke.peerPub.X != nil {
		peerPubDer, err = MarshalPublicKey(ke.peerPub)
		if err != nil {
			err = errors.New("sm2: marshal key exchange failed")
			return
		}
	}
	p = append(p, encodeLengthFieldBasedFrame(peerPubDer)...)
	// peerZ
	p = append(p, encodeLengthFieldBasedFrame(ke.peerZ)...)
	// r
	var r []byte
	if ke.r != nil {
		r = ke.r.Bytes()
	}
	p = append(p, encodeLengthFieldBasedFrame(r)...)
	// secret
	var secretDer []byte
	if ke.secret != nil && ke.secret.X != nil {
		secretDer, err = MarshalPublicKey(ke.secret)
		if err != nil {
			err = errors.New("sm2: marshal key exchange failed")
			return
		}
	}
	p = append(p, encodeLengthFieldBasedFrame(secretDer)...)
	// peerSecret
	var peerSecretDer []byte
	if ke.peerSecret != nil && ke.peerSecret.X != nil {
		peerSecretDer, err = MarshalPublicKey(ke.peerSecret)
		if err != nil {
			err = errors.New("sm2: marshal key exchange failed")
			return
		}
	}
	p = append(p, encodeLengthFieldBasedFrame(peerSecretDer)...)
	// w2
	var w2 []byte
	if ke.w2 != nil {
		w2 = ke.w2.Bytes()
	}
	p = append(p, encodeLengthFieldBasedFrame(w2)...)
	// w2Minus1
	var w2Minus1 []byte
	if ke.w2Minus1 != nil {
		w2Minus1 = ke.w2Minus1.Bytes()
	}
	p = append(p, encodeLengthFieldBasedFrame(w2Minus1)...)
	// v
	var vDer []byte
	if ke.v != nil && ke.v.X != nil {
		vDer, err = MarshalPublicKey(ke.v)
		if err != nil {
			err = errors.New("sm2: marshal key exchange failed")
			return
		}
	}
	p = append(p, encodeLengthFieldBasedFrame(vDer)...)
	// base64
	pp := make([]byte, base64.StdEncoding.EncodedLen(len(p)))
	base64.StdEncoding.Encode(pp, p)
	p = pp
	return
}

func initKeyExchange(ke *KeyExchange, r *big.Int) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r
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

func decodeLengthFieldBasedFrame(frame []byte) (p []byte, pLen uint64, err error) {
	if len(frame) < 8 {
		err = errors.New("invalid length field base frame")
		return
	}
	pLen = binary.BigEndian.Uint64(frame[0:8])
	if pLen == 0 {
		return
	}
	p = frame[8 : 8+pLen]
	return
}

func encodeLengthFieldBasedFrame(p []byte) (frame []byte) {
	frame = make([]byte, 0, 16)
	field := make([]byte, 8)
	pLen := len(p)
	binary.BigEndian.PutUint64(field, uint64(pLen))
	frame = append(frame, field...)
	if pLen > 0 {
		frame = append(frame, p...)
	}
	return
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
