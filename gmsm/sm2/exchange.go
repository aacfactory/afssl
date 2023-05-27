package sm2

import (
	"errors"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"math/big"
)

func keyExchange(keyLen int, ida, idb []byte, pri *PrivateKey, pub *PublicKey, rpri *PrivateKey, rpub *PublicKey, isInitiator bool) (k, s1, s2 []byte, err error) {
	curve := P256()
	N := curve.Params().N
	x2hat := keXHat(rpri.PublicKey.X)
	x2rb := new(big.Int).Mul(x2hat, rpri.D)
	tbt := new(big.Int).Add(pri.D, x2rb)
	tb := new(big.Int).Mod(tbt, N)
	if !curve.IsOnCurve(rpub.X, rpub.Y) {
		err = errors.New("sm2: ra not on curve")
		return
	}
	x1hat := keXHat(rpub.X)
	ramx1, ramy1 := curve.ScalarMult(rpub.X, rpub.Y, x1hat.Bytes())
	vxt, vyt := curve.Add(pub.X, pub.Y, ramx1, ramy1)

	vx, vy := curve.ScalarMult(vxt, vyt, tb.Bytes())
	pza := pub
	if isInitiator {
		pza = &pri.PublicKey
	}
	za, zaErr := ZA(pza, ida)

	if zaErr != nil {
		err = zaErr
		return
	}
	zero := new(big.Int)
	if vx.Cmp(zero) == 0 || vy.Cmp(zero) == 0 {
		err = errors.New("sm2: v is infinite")
	}
	pzb := pub
	if !isInitiator {
		pzb = &pri.PublicKey
	}
	zb, zbErr := ZA(pzb, idb)
	if zbErr != nil {
		err = zbErr
		return
	}
	kk, ok := kdf(keyLen, vx.Bytes(), vy.Bytes(), za, zb)
	if !ok {
		err = errors.New("sm2: zero key")
		return
	}
	k = kk
	var h1 []byte
	if isInitiator {
		h1 = bytesCombine(vx.Bytes(), za, zb, rpub.X.Bytes(), rpub.Y.Bytes(), rpri.X.Bytes(), rpri.Y.Bytes())
	} else {
		h1 = bytesCombine(vx.Bytes(), za, zb, rpri.X.Bytes(), rpri.Y.Bytes(), rpub.X.Bytes(), rpub.Y.Bytes())
	}
	s := sm3.Sum(h1)
	h2 := bytesCombine([]byte{0x02}, vy.Bytes(), s)
	s1 = sm3.Sum(h2)
	h3 := bytesCombine([]byte{0x03}, vy.Bytes(), s)
	s2 = sm3.Sum(h3)
	return
}

func keXHat(x *big.Int) (xul *big.Int) {
	buf := x.Bytes()
	for i := 0; i < len(buf)-16; i++ {
		buf[i] = 0
	}
	if len(buf) >= 16 {
		c := buf[len(buf)-16]
		buf[len(buf)-16] = c & 0x7f
	}

	r := new(big.Int).SetBytes(buf)
	_2w := new(big.Int).SetBytes([]byte{
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return r.Add(r, _2w)
}
