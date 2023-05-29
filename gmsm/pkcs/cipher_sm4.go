package pkcs

import (
	"encoding/asn1"
	"github.com/aacfactory/afssl/gmsm/sm4"
)

var (
	oidSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	oidSM4GCM = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
	oidSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
	oidSM4    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
)

func init() {
	RegisterCipher(oidSM4CBC, func() Cipher {
		return SM4CBC
	})
	RegisterCipher(oidSM4GCM, func() Cipher {
		return SM4GCM
	})
	RegisterCipher(oidSM4ECB, func() Cipher {
		return SM4ECB
	})
}

var SM4ECB = &ecbBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4ECB,
	},
}

var SM4CBC = &cbcBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4CBC,
	},
	ivSize: sm4.BlockSize,
}

var SM4GCM = &gcmBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4GCM,
	},
	nonceSize: 12,
}
