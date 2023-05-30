// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smx509

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"github.com/aacfactory/afssl/gmsm/sm9"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, a ed25519.PrivateKey (not
// a pointer), *sm2.PrivateKey, *sm9.SignPrivateKey, *sm9.EncryptPrivateKey, *sm9.SignMasterPrivateKey, *sm9.EncryptMasterPrivateKey,
// or a *ecdh.PrivateKey (for X25519). More types might be supported
// in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key any, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		// >>> ori
		//key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		//if err != nil {
		//	return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		//}
		// <<<
		// >>> change for sm2
		ecKey, parseErr := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if parseErr != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + parseErr.Error())
		}
		if namedCurveOID.Equal(oidNamedCurveP256SM2) {
			key, err = new(sm2.PrivateKey).FromECPrivateKey(ecKey)
		} else {
			key = ecKey
		}
		// <<<
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyX25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid X25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid X25519 private key: %v", err)
		}
		return ecdh.X25519().NewPrivateKey(curvePrivateKey)

	case privKey.Algo.Algorithm.Equal(oidSM9), privKey.Algo.Algorithm.Equal(oidSM9Sign), privKey.Algo.Algorithm.Equal(oidSM9Enc):
		return parseSM9PrivateKey(privKey)

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey,
// *ecdsa.PrivateKey, ed25519.PrivateKey (not a pointer),
// *sm2.PrivateKey, *sm9.SignPrivateKey, *sm9.EncryptPrivateKey, *sm9.SignMasterPrivateKey, *sm9.EncryptMasterPrivateKey,
// and *ecdh.PrivateKey.
// Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
		}
		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *ecdh.PrivateKey:
		if k.Curve() == ecdh.X25519() {
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyX25519,
			}
			var err error
			if privKey.PrivateKey, err = asn1.Marshal(k.Bytes()); err != nil {
				return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
			}
		} else {
			oid, ok := oidFromECDHCurve(k.Curve())
			if !ok {
				return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
			}
			oidBytes, err := asn1.Marshal(oid)
			if err != nil {
				return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
			}
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyECDSA,
				Parameters: asn1.RawValue{
					FullBytes: oidBytes,
				},
			}
			if privKey.PrivateKey, err = marshalECDHPrivateKey(k); err != nil {
				return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
			}
		}

	case *sm2.PrivateKey:
		// >>> add for sm2
		return MarshalPKCS8PrivateKey(&k.PrivateKey)
		// <<<
	case *sm9.SignPrivateKey:
		return marshalPKCS8SM9SignPrivateKey(k)
	case *sm9.EncryptPrivateKey:
		return marshalPKCS8SM9EncPrivateKey(k)
	case *sm9.SignMasterPrivateKey:
		return marshalPKCS8SM9SignMasterPrivateKey(k)
	case *sm9.EncryptMasterPrivateKey:
		return marshalPKCS8SM9EncMasterPrivateKey(k)
	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}

var (
	oidSM9     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302}
	oidSM9Sign = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}
	oidSM9Enc  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 3}
)

type sm9PrivateKey struct {
	PrivateKey asn1.RawValue
	PublicKey  asn1.RawValue
}

func marshalPKCS8SM9SignPrivateKey(k *sm9.SignPrivateKey) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm:  oidSM9Sign,
		Parameters: asn1.NullRawValue,
	}

	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.MasterPublic().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
	key.PublicKey.FullBytes = pubasn1

	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 sign private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9EncPrivateKey(k *sm9.EncryptPrivateKey) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm:  oidSM9Enc,
		Parameters: asn1.NullRawValue,
	}
	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.MasterPublic().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
	key.PublicKey.FullBytes = pubasn1

	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 encrypt private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9SignMasterPrivateKey(k *sm9.SignMasterPrivateKey) ([]byte, error) {
	var privKey pkcs8
	oidBytes, err := asn1.Marshal(oidSM9Sign)
	if err != nil {
		return nil, errors.New("x509: failed to marshal SM9 OID: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidSM9,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.Public().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
	key.PublicKey.FullBytes = pubasn1

	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 sign master private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9EncMasterPrivateKey(k *sm9.EncryptMasterPrivateKey) ([]byte, error) {
	var privKey pkcs8
	oidBytes, err := asn1.Marshal(oidSM9Enc)
	if err != nil {
		return nil, errors.New("x509: failed to marshal SM9 OID: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidSM9,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.Public().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
	key.PublicKey.FullBytes = pubasn1

	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 encrypt master private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8ECPrivateKey(k *ecdsa.PrivateKey) ([]byte, error) {
	var privKey pkcs8
	oid, ok := oidFromNamedCurve(k.Curve)
	if !ok {
		return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
	}

	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
	}

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
		return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func parseSM9PrivateKey(privKey pkcs8) (key interface{}, err error) {
	switch {
	case privKey.Algo.Algorithm.Equal(oidSM9Sign):
		sm9SignKey := new(sm9.SignPrivateKey)
		err = sm9SignKey.UnmarshalASN1(privKey.PrivateKey)
		if err != nil {
			return
		}
		key = sm9SignKey
		return
	case privKey.Algo.Algorithm.Equal(oidSM9Enc):
		sm9EncKey := new(sm9.EncryptPrivateKey)
		err = sm9EncKey.UnmarshalASN1(privKey.PrivateKey)
		if err != nil {
			return
		}
		key = sm9EncKey
		return
	default:
		bytes := privKey.Algo.Parameters.FullBytes
		detailOID := new(asn1.ObjectIdentifier)
		_, err = asn1.Unmarshal(bytes, detailOID)
		if err != nil {
			return
		}
		switch {
		case oidSM9Sign.Equal(*detailOID):
			sm9SignMasterKey := new(sm9.SignMasterPrivateKey)
			err = sm9SignMasterKey.UnmarshalASN1(privKey.PrivateKey)
			if err != nil {
				return
			}
			key = sm9SignMasterKey
			return
		case oidSM9Enc.Equal(*detailOID):
			sm9EncMasterKey := new(sm9.EncryptMasterPrivateKey)
			err = sm9EncMasterKey.UnmarshalASN1(privKey.PrivateKey)
			if err != nil {
				return
			}
			key = sm9EncMasterKey
			return
		}
		return nil, errors.New("not support yet")
	}
}
