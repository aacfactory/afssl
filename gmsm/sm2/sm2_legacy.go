package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/aacfactory/afssl/gmsm/kdf"
	"github.com/aacfactory/afssl/gmsm/sm2/sm2ec"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type invertible interface {
	Inverse(k *big.Int) *big.Int
}

type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

var errZeroParam = errors.New("zero parameter")

func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	key := new(PrivateKey)
	key.PrivateKey = *priv
	sig, err := SignASN1(rand, key, hash, nil)
	if err != nil {
		return nil, nil, err
	}

	r, s = new(big.Int), new(big.Int)
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1 from SignASN1")
	}
	return r, s, nil
}

func signLegacy(priv *PrivateKey, csprng io.Reader, hash []byte) (sig []byte, err error) {
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	var k, r, s *big.Int
	e := hashToInt(hash, c)
	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				return nil, err
			}

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes()) // (x, y) = k*G
			r.Add(r, e)                                 // r = x + e
			r.Mod(r, N)                                 // r = (x + e) mod N
			if r.Sign() != 0 {
				t := new(big.Int).Add(r, k)
				if t.Cmp(N) != 0 { // if r != 0 && (r + k) != N then ok
					break
				}
			}
		}
		s = new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, s)
		dp1 := new(big.Int).Add(priv.D, one)

		var dp1Inv *big.Int

		if in, ok := priv.Curve.(invertible); ok {
			dp1Inv = in.Inverse(dp1)
		} else {
			dp1Inv = fermatInverse(dp1, N) // N != 0
		}

		s.Mul(s, dp1Inv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return encodeSignature(r.Bytes(), s.Bytes())
}

func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

func SignWithSM2(rand io.Reader, priv *ecdsa.PrivateKey, uid, msg []byte) (r, s *big.Int, err error) {
	digest, err := calculateSM2Hash(&priv.PublicKey, msg, uid)
	if err != nil {
		return nil, nil, err
	}

	return Sign(rand, priv, digest)
}

func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	sig, err := encodeSignature(r.Bytes(), s.Bytes())
	if err != nil {
		return false
	}
	return VerifyASN1(pub, hash, sig)
}

func verifyLegacy(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)

	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	e := hashToInt(hash, c)
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(s.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x, _ = c.Add(x1, y1, x2, y2)
	}

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func VerifyWithSM2(pub *ecdsa.PublicKey, uid, msg []byte, r, s *big.Int) bool {
	digest, err := calculateSM2Hash(pub, msg, uid)
	if err != nil {
		return false
	}
	return Verify(pub, digest, r, s)
}

var (
	one = new(big.Int).SetInt64(1)
)

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

func encryptLegacy(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncryptorOpts) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)

	var retryCount int = 0
	for {
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}

		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		c1 := opts.pointMarshalMode.mashal(curve, x1, y1)

		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		c2 := kdf.Kdf(sm3.New(), append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if subtle.ConstantTimeCompare(c2, nil) == 1 {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
			}
			continue
		}

		subtle.XORBytes(c2, msg, c2)

		c3 := calculateC3(curve, x2, y2, msg)

		if opts.ciphertextEncoding == encodingPlain {
			if opts.ciphertextSplicingOrder == C1C3C2 {
				// c1 || c3 || c2
				return append(append(c1, c3...), c2...), nil
			}
			return append(append(c1, c2...), c3...), nil
		}
		return mashalASN1Ciphertext(x1, y1, c2, c3)
	}
}

func calculateC3(curve elliptic.Curve, x2, y2 *big.Int, msg []byte) []byte {
	md := sm3.New()
	md.Write(toBytes(curve, x2))
	md.Write(msg)
	md.Write(toBytes(curve, y2))
	return md.Sum(nil)
}

func mashalASN1Ciphertext(x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(x1)
		b.AddASN1BigInt(y1)
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncryptorOpts) ([]byte, error) {
	if opts == nil {
		opts = defaultEncryptorOpts
	}
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	curve := sm2ec.P256()
	c1 := opts.pointMarshalMode.mashal(curve, x1, y1)
	if opts.ciphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	return append(append(c1, c2...), c3...), nil
}

func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	if ciphertext[0] == 0x30 {
		return nil, errors.New("sm2: invalid plain encoding ciphertext")
	}
	curve := sm2ec.P256()
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+sm3.Size {
		return nil, errCiphertextTooShort
	}
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c2, c3 []byte

	if from == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}
	return mashalASN1Ciphertext(x1, y1, c2, c3)
}

func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	curve := sm2ec.P256()
	if from == to {
		return ciphertext, nil
	}
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+sm3.Size {
		return nil, errCiphertextTooShort
	}

	_, _, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c1, c2, c3 []byte

	c1 = ciphertext[:c3Start]
	if from == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}

	result := make([]byte, ciphertextLen)
	copy(result, c1)
	if to == C1C3C2 {
		// c1 || c3 || c2
		copy(result[c3Start:], c3)
		copy(result[c3Start+sm3.Size:], c2)
	} else {
		// c1 || c2 || c3
		copy(result[c3Start:], c2)
		copy(result[ciphertextLen-sm3.Size:], c3)
	}
	return result, nil
}

func decryptASN1(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}
	return rawDecrypt(priv, x1, y1, c2, c3)
}

func rawDecrypt(priv *PrivateKey, x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	curve := priv.Curve
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())
	msgLen := len(c2)
	msg := kdf.Kdf(sm3.New(), append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if subtle.ConstantTimeCompare(c2, nil) == 1 {
		return nil, ErrDecryption
	}

	subtle.XORBytes(msg, c2, msg)

	u := calculateC3(curve, x2, y2, msg)
	if subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

func decryptLegacy(priv *PrivateKey, ciphertext []byte, opts *DecryptorOpts) ([]byte, error) {
	splicingOrder := C1C3C2
	if opts != nil {
		if opts.ciphertextEncoding == encodingAsn1 {
			return decryptASN1(priv, ciphertext)
		}
		splicingOrder = opts.cipherTextSplicingOrder
	}
	if ciphertext[0] == 0x30 {
		return decryptASN1(priv, ciphertext)
	}
	ciphertextLen := len(ciphertext)
	curve := priv.Curve
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}

	var c2, c3 []byte
	if splicingOrder == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}

	return rawDecrypt(priv, x1, y1, c2, c3)
}

func bytes2Point(curve elliptic.Curve, bytes []byte) (*big.Int, *big.Int, int, error) {
	if len(bytes) < 1+(curve.Params().BitSize/8) {
		return nil, nil, 0, fmt.Errorf("sm2: invalid bytes length %d", len(bytes))
	}
	format := bytes[0]
	byteLen := (curve.Params().BitSize + 7) >> 3
	switch format {
	case uncompressed, hybrid06, hybrid07: // what's the hybrid format purpose?
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("sm2: invalid point uncompressed/hybrid form bytes length %d", len(bytes))
		}
		data := make([]byte, 1+byteLen*2)
		data[0] = uncompressed
		copy(data[1:], bytes[1:1+byteLen*2])
		x, y := sm2ec.Unmarshal(curve, data)
		if x == nil || y == nil {
			return nil, nil, 0, fmt.Errorf("sm2: point is not on curve %s", curve.Params().Name)
		}
		return x, y, 1 + byteLen*2, nil
	case compressed02, compressed03:
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("sm2: invalid point compressed form bytes length %d", len(bytes))
		}
		if strings.HasPrefix(curve.Params().Name, "P-") || strings.EqualFold(curve.Params().Name, sm2ec.P256().Params().Name) {
			x, y := sm2ec.UnmarshalCompressed(curve, bytes[:1+byteLen])
			if x == nil || y == nil {
				return nil, nil, 0, fmt.Errorf("sm2: point is not on curve %s", curve.Params().Name)
			}
			return x, y, 1 + byteLen, nil
		}
		return nil, nil, 0, fmt.Errorf("sm2: unsupport point form %d, curve %s", format, curve.Params().Name)
	}
	return nil, nil, 0, fmt.Errorf("sm2: unknown point form %d", format)
}

func (mode pointMarshalMode) mashal(curve elliptic.Curve, x, y *big.Int) []byte {
	switch mode {
	case MarshalCompressed:
		return elliptic.MarshalCompressed(curve, x, y)
	case MarshalHybrid:
		buffer := elliptic.Marshal(curve, x, y)
		buffer[0] = byte(y.Bit(0)) | hybrid06
		return buffer
	default:
		return elliptic.Marshal(curve, x, y)
	}
}
