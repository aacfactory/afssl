package sm2

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type privateKey struct {
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

type pbesKDfs struct {
	IdPBKDF2    asn1.ObjectIdentifier
	Pkdf2Params pkdfParams
}

type pkdfParams struct {
	Salt           []byte
	IterationCount int
	Prf            pkix.AlgorithmIdentifier
}

type pbesEncs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type pbesParams struct {
	KeyDerivationFunc pbesKDfs // PBES2-KDFs
	EncryptionScheme  pbesEncs // PBES2-Encs
}

type pbesAlgorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	Pbes2Params pbesParams
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pbesAlgorithms
	EncryptedData       []byte
}
