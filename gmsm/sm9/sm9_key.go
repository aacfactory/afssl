package sm9

import (
	"encoding/pem"

	"errors"
	"io"
	"math/big"
	"sync"

	"github.com/aacfactory/afssl/gmsm/internal/bigmod"
	"github.com/aacfactory/afssl/gmsm/sm9/bn256"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type SignMasterPrivateKey struct {
	SignMasterPublicKey
	D *big.Int
}

type SignMasterPublicKey struct {
	MasterPublicKey *bn256.G2
	pairOnce        sync.Once
	basePoint       *bn256.GT
	tableGenOnce    sync.Once
	table           *[32 * 2]bn256.GTFieldTable
}

type SignPrivateKey struct {
	PrivateKey *bn256.G1
	SignMasterPublicKey
}

type EncryptMasterPrivateKey struct {
	EncryptMasterPublicKey
	D *big.Int
}

type EncryptMasterPublicKey struct {
	MasterPublicKey *bn256.G1
	pairOnce        sync.Once
	basePoint       *bn256.GT
	tableGenOnce    sync.Once
	table           *[32 * 2]bn256.GTFieldTable
}

type EncryptPrivateKey struct {
	PrivateKey *bn256.G2
	EncryptMasterPublicKey
}

func GenerateSignMasterKey(rand io.Reader) (*SignMasterPrivateKey, error) {
	k, err := randomScalar(rand)
	if err != nil {
		return nil, err
	}
	kBytes := k.Bytes(orderNat)
	p, err := new(bn256.G2).ScalarBaseMult(kBytes)
	if err != nil {
		return nil, err
	}

	priv := new(SignMasterPrivateKey)
	priv.D = new(big.Int).SetBytes(kBytes)
	priv.MasterPublicKey = p
	return priv, nil
}

func (master *SignMasterPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BigInt(master.D)
	return b.Bytes()
}

func (master *SignMasterPrivateKey) UnmarshalASN1(der []byte) error {
	input := cryptobyte.String(der)
	d := &big.Int{}
	var inner cryptobyte.String
	var pubBytes []byte
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(d) {
			return errors.New("sm9: invalid sign master private key asn1 data")
		}
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return errors.New("sm9: invalid sign master public key asn1 data")
		}
	} else if !input.ReadASN1Integer(d) || !input.Empty() {
		return errors.New("sm9: invalid sign master private key asn1 data")
	}
	master.D = d
	p, err := new(bn256.G2).ScalarBaseMult(bn256.NormalizeScalar(d.Bytes()))
	if err != nil {
		return err
	}
	master.MasterPublicKey = p
	return nil
}

func (master *SignMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*SignPrivateKey, error) {
	var id []byte
	id = append(id, uid...)
	id = append(id, hid)

	t1Nat := hashH1(id)

	d, err := bigmod.NewNat().SetBytes(master.D.Bytes(), orderNat)
	if err != nil {
		return nil, err
	}

	t1Nat.Add(d, orderNat)
	if t1Nat.IsZero() == 1 {
		return nil, errors.New("sm9: need to re-generate sign master private key")
	}

	t1Nat = bigmod.NewNat().Exp(t1Nat, orderMinus2, orderNat)
	t1Nat.Mul(d, orderNat)

	priv := new(SignPrivateKey)
	priv.SignMasterPublicKey = master.SignMasterPublicKey
	g1, err := new(bn256.G1).ScalarBaseMult(t1Nat.Bytes(orderNat))
	if err != nil {
		return nil, err
	}
	priv.PrivateKey = g1

	return priv, nil
}

func (master *SignMasterPrivateKey) Public() *SignMasterPublicKey {
	return &master.SignMasterPublicKey
}

func (pub *SignMasterPublicKey) pair() *bn256.GT {
	pub.pairOnce.Do(func() {
		pub.basePoint = bn256.Pair(bn256.Gen1, pub.MasterPublicKey)
	})
	return pub.basePoint
}

func (pub *SignMasterPublicKey) generatorTable() *[32 * 2]bn256.GTFieldTable {
	pub.tableGenOnce.Do(func() {
		pub.table = bn256.GenerateGTFieldTable(pub.pair())
	})
	return pub.table
}

func (pub *SignMasterPublicKey) ScalarBaseMult(scalar []byte) (*bn256.GT, error) {
	tables := pub.generatorTable()
	return bn256.ScalarBaseMultGT(tables, scalar)
}

func (pub *SignMasterPublicKey) GenerateUserPublicKey(uid []byte, hid byte) *bn256.G2 {
	var buffer []byte
	buffer = append(buffer, uid...)
	buffer = append(buffer, hid)
	h1 := hashH1(buffer)
	p, err := new(bn256.G2).ScalarBaseMult(h1.Bytes(orderNat))
	if err != nil {
		panic(err)
	}
	p.Add(p, pub.MasterPublicKey)
	return p
}

func (pub *SignMasterPublicKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.MasterPublicKey.MarshalUncompressed())
	return b.Bytes()
}

func (pub *SignMasterPublicKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.MasterPublicKey.MarshalCompressed())
	return b.Bytes()
}

func unmarshalG2(bytes []byte) (*bn256.G2, error) {
	g2 := new(bn256.G2)
	switch bytes[0] {
	case 4:
		_, err := g2.Unmarshal(bytes[1:])
		if err != nil {
			return nil, err
		}
	case 2, 3:
		_, err := g2.UnmarshalCompressed(bytes)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("sm9: invalid point identity byte")
	}
	return g2, nil
}

func (pub *SignMasterPublicKey) UnmarshalRaw(bytes []byte) error {
	g2, err := unmarshalG2(bytes)
	if err != nil {
		return err
	}
	pub.MasterPublicKey = g2
	return nil
}

func (pub *SignMasterPublicKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) ||
			!inner.Empty() {
			return errors.New("sm9: invalid sign master public key asn1 data")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid sign master public key asn1 data")
	}
	return pub.UnmarshalRaw(bytes)
}

func (pub *SignMasterPublicKey) ParseFromPEM(data []byte) error {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return errors.New("sm9: failed to parse PEM block")
	}
	return pub.UnmarshalASN1(block.Bytes)
}

func (priv *SignPrivateKey) MasterPublic() *SignMasterPublicKey {
	return &priv.SignMasterPublicKey
}

func (priv *SignPrivateKey) SetMasterPublicKey(pub *SignMasterPublicKey) {
	if priv.SignMasterPublicKey.MasterPublicKey == nil {
		priv.SignMasterPublicKey = *pub
	}
}

func (priv *SignPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.PrivateKey.MarshalUncompressed())
	return b.Bytes()
}

func (priv *SignPrivateKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.PrivateKey.MarshalCompressed())
	return b.Bytes()
}

func unmarshalG1(bytes []byte) (*bn256.G1, error) {
	g := new(bn256.G1)
	switch bytes[0] {
	case 4:
		_, err := g.Unmarshal(bytes[1:])
		if err != nil {
			return nil, err
		}
	case 2, 3:
		_, err := g.UnmarshalCompressed(bytes)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("sm9: invalid point identity byte")
	}
	return g, nil
}

func (priv *SignPrivateKey) UnmarshalRaw(bytes []byte) error {
	g, err := unmarshalG1(bytes)
	if err != nil {
		return err
	}
	priv.PrivateKey = g
	return nil
}

func (priv *SignPrivateKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	var pubBytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) {
			return errors.New("sm9: invalid sign user private key asn1 data")
		}
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return errors.New("sm9: invalid sign master public key asn1 data")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid sign user private key asn1 data")
	}
	err := priv.UnmarshalRaw(bytes)
	if err != nil {
		return err
	}
	if len(pubBytes) > 0 {
		masterPK := new(SignMasterPublicKey)
		err = masterPK.UnmarshalRaw(pubBytes)
		if err != nil {
			return err
		}
		priv.SetMasterPublicKey(masterPK)
	}
	return nil
}

func GenerateEncryptMasterKey(rand io.Reader) (*EncryptMasterPrivateKey, error) {
	k, err := randomScalar(rand)
	if err != nil {
		return nil, err
	}
	kBytes := k.Bytes(orderNat)

	priv := new(EncryptMasterPrivateKey)
	priv.D = new(big.Int).SetBytes(kBytes)
	p, err := new(bn256.G1).ScalarBaseMult(kBytes)
	if err != nil {
		panic(err)
	}
	priv.MasterPublicKey = p
	return priv, nil
}

func (master *EncryptMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*EncryptPrivateKey, error) {
	var id []byte
	id = append(id, uid...)
	id = append(id, hid)

	t1Nat := hashH1(id)

	d, err := bigmod.NewNat().SetBytes(master.D.Bytes(), orderNat)
	if err != nil {
		return nil, err
	}

	t1Nat.Add(d, orderNat)
	if t1Nat.IsZero() == 1 {
		return nil, errors.New("sm9: need to re-generate encrypt master private key")
	}

	t1Nat = bigmod.NewNat().Exp(t1Nat, orderMinus2, orderNat)
	t1Nat.Mul(d, orderNat)

	priv := new(EncryptPrivateKey)
	priv.EncryptMasterPublicKey = master.EncryptMasterPublicKey
	p, err := new(bn256.G2).ScalarBaseMult(t1Nat.Bytes(orderNat))
	if err != nil {
		panic(err)
	}
	priv.PrivateKey = p

	return priv, nil
}

func (master *EncryptMasterPrivateKey) Public() *EncryptMasterPublicKey {
	return &master.EncryptMasterPublicKey
}

func (master *EncryptMasterPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BigInt(master.D)
	return b.Bytes()
}

func (master *EncryptMasterPrivateKey) UnmarshalASN1(der []byte) error {
	input := cryptobyte.String(der)
	d := &big.Int{}
	var inner cryptobyte.String
	var pubBytes []byte
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(d) {
			return errors.New("sm9: invalid encrypt master private key asn1 data")
		}
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return errors.New("sm9: invalid encrypt master public key asn1 data")
		}
	} else if !input.ReadASN1Integer(d) || !input.Empty() {
		return errors.New("sm9: invalid encrypt master private key asn1 data")
	}
	master.D = d
	p, err := new(bn256.G1).ScalarBaseMult(bn256.NormalizeScalar(d.Bytes()))
	if err != nil {
		return err
	}
	master.MasterPublicKey = p
	return nil
}

func (pub *EncryptMasterPublicKey) pair() *bn256.GT {
	pub.pairOnce.Do(func() {
		pub.basePoint = bn256.Pair(pub.MasterPublicKey, bn256.Gen2)
	})
	return pub.basePoint
}

func (pub *EncryptMasterPublicKey) generatorTable() *[32 * 2]bn256.GTFieldTable {
	pub.tableGenOnce.Do(func() {
		pub.table = bn256.GenerateGTFieldTable(pub.pair())
	})
	return pub.table
}

func (pub *EncryptMasterPublicKey) ScalarBaseMult(scalar []byte) (*bn256.GT, error) {
	tables := pub.generatorTable()
	return bn256.ScalarBaseMultGT(tables, scalar)
}

func (pub *EncryptMasterPublicKey) GenerateUserPublicKey(uid []byte, hid byte) *bn256.G1 {
	var buffer []byte
	buffer = append(buffer, uid...)
	buffer = append(buffer, hid)
	h1 := hashH1(buffer)
	p, err := new(bn256.G1).ScalarBaseMult(h1.Bytes(orderNat))
	if err != nil {
		panic(err)
	}
	p.Add(p, pub.MasterPublicKey)
	return p
}

func (pub *EncryptMasterPublicKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.MasterPublicKey.MarshalUncompressed())
	return b.Bytes()
}

func (pub *EncryptMasterPublicKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.MasterPublicKey.MarshalCompressed())
	return b.Bytes()
}

func (pub *EncryptMasterPublicKey) UnmarshalRaw(bytes []byte) error {
	g, err := unmarshalG1(bytes)
	if err != nil {
		return err
	}
	pub.MasterPublicKey = g
	return nil
}

func (pub *EncryptMasterPublicKey) ParseFromPEM(data []byte) error {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return errors.New("sm9: failed to parse PEM block")
	}
	return pub.UnmarshalASN1(block.Bytes)
}

func (pub *EncryptMasterPublicKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) ||
			!inner.Empty() {
			return errors.New("sm9: invalid encrypt master public key asn1 data")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid encrypt master public key asn1 data")
	}
	return pub.UnmarshalRaw(bytes)
}

func (priv *EncryptPrivateKey) MasterPublic() *EncryptMasterPublicKey {
	return &priv.EncryptMasterPublicKey
}

func (priv *EncryptPrivateKey) SetMasterPublicKey(pub *EncryptMasterPublicKey) {
	if priv.EncryptMasterPublicKey.MasterPublicKey == nil {
		priv.EncryptMasterPublicKey = *pub
	}
}

func (priv *EncryptPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.PrivateKey.MarshalUncompressed())
	return b.Bytes()
}

func (priv *EncryptPrivateKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.PrivateKey.MarshalCompressed())
	return b.Bytes()
}

func (priv *EncryptPrivateKey) UnmarshalRaw(bytes []byte) error {
	g, err := unmarshalG2(bytes)
	if err != nil {
		return err
	}
	priv.PrivateKey = g
	return nil
}

func (priv *EncryptPrivateKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	var pubBytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) {
			return errors.New("sm9: invalid encrypt user private key asn1 data")
		}
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return errors.New("sm9: invalid encrypt master public key asn1 data")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid encrypt user private key asn1 data")
	}
	err := priv.UnmarshalRaw(bytes)
	if err != nil {
		return err
	}
	if len(pubBytes) > 0 {
		masterPK := new(EncryptMasterPublicKey)
		err = masterPK.UnmarshalRaw(pubBytes)
		if err != nil {
			return err
		}
		priv.SetMasterPublicKey(masterPK)
	}
	return nil
}
