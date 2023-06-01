package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"reflect"
)

var (
	oidSM2               = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func UnmarshalPrivateKey(der []byte) (key *PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &pkcs8{}); err == nil {
			return nil, errors.New("sm2: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)")
		}
		return nil, errors.New("sm2: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != 1 {
		return nil, fmt.Errorf("sm2: unknown EC private key version %d", privKey.Version)
	}

	curve := P256()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("sm2: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("sm2: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return new(PrivateKey).FromECPrivateKey(priv)
}

func (pri *PrivateKey) Marshal() ([]byte, error) {
	key := &pri.PrivateKey
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("sm2: invalid elliptic key public key")
	}
	pk := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(pk),
		NamedCurveOID: oidNamedCurveP256SM2,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

func UnmarshalPublicKey(der []byte) (key *ecdsa.PublicKey, err error) {
	var ppk pkixPublicKey
	if _, err = asn1.Unmarshal(der, &ppk); err != nil {
		return
	}
	if !reflect.DeepEqual(ppk.Algo.Algorithm, oidSM2) {
		return nil, errors.New("sm2: not sm2 elliptic curve")
	}
	curve := P256()
	x, y := elliptic.Unmarshal(curve, ppk.BitString.Bytes)
	key = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return
}

func MarshalPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	var r pkixPublicKey
	var algo pkix.AlgorithmIdentifier

	if pub.Curve.Params() != P256().Params() {
		return nil, errors.New("sm2: unsupported elliptic curve")
	}
	algo.Algorithm = oidSM2
	algo.Parameters.Class = 0
	algo.Parameters.Tag = 6
	algo.Parameters.IsCompound = false
	algo.Parameters.FullBytes = []byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}
	r.Algo = algo
	r.BitString = asn1.BitString{Bytes: elliptic.Marshal(pub.Curve, pub.X, pub.Y)}
	return asn1.Marshal(r)
}
