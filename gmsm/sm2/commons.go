package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"io"
	"math/big"
)

var (
	one = new(big.Int).SetInt64(1)
	two = new(big.Int).SetInt64(2)
)

func Sign(pri *PrivateKey, msg, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	digest, err := pri.PublicKey.Digest(msg, uid)
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := pri.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errors.New("sm2: zero parameter")
	}
	var k *big.Int
	for {
		for {
			k, err = randFieldElement(c, random)
			if err != nil {
				r = nil
				return
			}
			r, _ = pri.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		rD := new(big.Int).Mul(pri.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(pri.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one_ := new(big.Int).SetInt64(1)
	if r.Cmp(one_) < 0 || s.Cmp(one_) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = defaultUid
	}
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func Encrypt(pub *PublicKey, data []byte, random io.Reader, mode int) ([]byte, error) {
	length := len(data)
	for {
		c := make([]byte, 0, 1)
		curve := pub.Curve
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		if n := len(x2Buf); n < 32 {
			x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
		}
		c = append(c, x1Buf...)
		c = append(c, y1Buf...)
		tm := make([]byte, 0, 1)
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)
		h := sm3.Sum(tm)
		c = append(c, h...)
		ct, ok := kdf(length, x2Buf, y2Buf)
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[96+i] ^= data[i]
		}
		switch mode {

		case C1C3C2:
			return append([]byte{0x04}, c...), nil
		case C1C2C3:
			c1 := make([]byte, 64)
			c2 := make([]byte, len(c)-96)
			c3 := make([]byte, 32)
			copy(c1, c[:64])
			copy(c3, c[64:96])
			copy(c2, c[96:])
			ciphertext := make([]byte, 0, 1)
			ciphertext = append(ciphertext, c1...)
			ciphertext = append(ciphertext, c2...)
			ciphertext = append(ciphertext, c3...)
			return append([]byte{0x04}, ciphertext...), nil
		default:
			return append([]byte{0x04}, c...), nil
		}
	}
}

func Decrypt(pri *PrivateKey, data []byte, mode int) ([]byte, error) {
	switch mode {
	case C1C3C2:
		data = data[1:]
	case C1C2C3:
		data = data[1:]
		c1 := make([]byte, 64)
		c2 := make([]byte, len(data)-96)
		c3 := make([]byte, 32)
		copy(c1, data[:64])
		copy(c2, data[64:len(data)-32])
		copy(c3, data[len(data)-32:])
		c := make([]byte, 0, 1)
		c = append(c, c1...)
		c = append(c, c3...)
		c = append(c, c2...)
		data = c
	default:
		data = data[1:]
	}
	length := len(data) - 96
	curve := pri.Curve
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	x2, y2 := curve.ScalarMult(x, y, pri.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
	}
	if n := len(y2Buf); n < 32 {
		y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
	}
	c, ok := kdf(length, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("sm2: failed to decrypt")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+96]
	}
	tm := make([]byte, 0, 1)
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)
	h := sm3.Sum(tm)
	if bytes.Compare(h, data[64:96]) != 0 {
		return c, errors.New("sm2: failed to decrypt")
	}
	return c, nil
}

func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data, rand, C1C3C2)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher, C1C3C2)
}

func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	uidLen := len(uid)
	if uidLen >= 8192 {
		return []byte{}, errors.New("sm2: uid too large")
	}
	entla := uint16(8 * uidLen)
	za.Write([]byte{byte((entla >> 8) & 0xFF)})
	za.Write([]byte{byte(entla & 0xFF)})
	if uidLen > 0 {
		za.Write(uid)
	}
	za.Write(p256ToBig(&p256.a).Bytes())
	za.Write(p256.B.Bytes())
	za.Write(p256.Gx.Bytes())
	za.Write(p256.Gy.Bytes())

	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()
	if n := len(xBuf); n < 32 {
		xBuf = append(zeroByteSlice()[:32-n], xBuf...)
	}
	if n := len(yBuf); n < 32 {
		yBuf = append(zeroByteSlice()[:32-n], yBuf...)
	}
	za.Write(xBuf)
	za.Write(yBuf)
	return za.Sum(nil)[:32], nil
}

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}
