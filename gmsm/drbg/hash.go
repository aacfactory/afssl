package drbg

import (
	"encoding/binary"
	"errors"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"hash"
	"time"
)

const hashSeedSize = 55
const hashMaxSeedSize = 111

func NewHash(newHash func() hash.Hash, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*Hash, error) {
	hd := &Hash{}

	hd.gm = gm
	hd.newHash = newHash
	hd.setSecurityLevel(securityLevel)

	md := newHash()
	hd.hashSize = md.Size()

	if len(entropy) == 0 || (hd.gm && len(entropy) < hd.hashSize) || len(entropy) >= MaxBytes {
		return nil, errors.New("invalid entropy length")
	}

	if len(nonce) == 0 || (hd.gm && len(nonce) < hd.hashSize/2) || len(nonce) >= MaxBytes>>1 {
		return nil, errors.New("invalid nonce length")
	}

	if len(personalization) >= MaxBytes {
		return nil, errors.New("personalization is too long")
	}

	if hd.hashSize <= sm3.Size {
		hd.v = make([]byte, hashSeedSize)
		hd.c = make([]byte, hashSeedSize)
		hd.seedLength = hashSeedSize
	} else {
		hd.v = make([]byte, hashMaxSeedSize)
		hd.c = make([]byte, hashMaxSeedSize)
		hd.seedLength = hashMaxSeedSize
	}
	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)

	seed := hd.derive(seedMaterial, hd.seedLength)
	copy(hd.v, seed)

	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.derive(temp, hd.seedLength)
	copy(hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()

	return hd, nil
}

func NewNistHash(newHash func() hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*Hash, error) {
	return NewHash(newHash, securityLevel, false, entropy, nonce, personalization)
}

func NewGmHash(securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*Hash, error) {
	return NewHash(sm3.New, securityLevel, true, entropy, nonce, personalization)
}

type Hash struct {
	Base
	newHash  func() hash.Hash
	c        []byte
	hashSize int
}

func (hd *Hash) Reseed(entropy, additional []byte) error {
	if len(entropy) == 0 || (hd.gm && len(entropy) < hd.hashSize) || len(entropy) >= MaxBytes {
		return errors.New("invalid entropy length")
	}

	if len(additional) >= MaxBytes {
		return errors.New("additional input too long")
	}
	seedMaterial := make([]byte, len(entropy)+hd.seedLength+len(additional)+1)
	seedMaterial[0] = 1
	if hd.gm {
		copy(seedMaterial[1:], entropy)
		copy(seedMaterial[len(entropy)+1:], hd.v)
	} else {
		copy(seedMaterial[1:], hd.v)
		copy(seedMaterial[hd.seedLength+1:], entropy)
	}
	copy(seedMaterial[len(entropy)+hd.seedLength+1:], additional)

	seed := hd.derive(seedMaterial, hd.seedLength)

	copy(hd.v, seed)
	temp := make([]byte, hd.seedLength+1)

	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.derive(temp, hd.seedLength)
	copy(hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *Hash) addW(w []byte) {
	t := make([]byte, hd.seedLength)
	copy(t[hd.seedLength-len(w):], w)
	add(t, hd.v, hd.seedLength)
}

func (hd *Hash) addC() {
	add(hd.c, hd.v, hd.seedLength)
}

func (hd *Hash) addH() {
	md := hd.newHash()
	md.Write([]byte{0x03})
	md.Write(hd.v)
	hd.addW(md.Sum(nil))
}

func (hd *Hash) addReseedCounter() {
	t := make([]byte, hd.seedLength)
	binary.BigEndian.PutUint64(t[hd.seedLength-8:], hd.reseedCounter)
	add(t, hd.v, hd.seedLength)
}

func (hd *Hash) MaxBytesPerRequest() int {
	if hd.gm {
		return hd.hashSize
	}
	return MaxBytesPerGenerate
}

func (hd *Hash) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return ErrReseedRequired
	}
	if (hd.gm && len(b) > hd.hashSize) || (!hd.gm && len(b) > MaxBytesPerGenerate) {
		return errors.New("too many bytes requested")
	}
	md := hd.newHash()
	m := len(b)

	if len(additional) > 0 {
		md.Write([]byte{0x02})
		md.Write(hd.v)
		md.Write(additional)
		w := md.Sum(nil)
		md.Reset()
		hd.addW(w)
	}
	if hd.gm {
		md.Write(hd.v)
		copy(b, md.Sum(nil))
		md.Reset()
	} else {
		limit := uint64(m+md.Size()-1) / uint64(md.Size())
		data := make([]byte, hd.seedLength)
		copy(data, hd.v)
		for i := 0; i < int(limit); i++ {
			md.Write(data)
			copy(b[i*md.Size():], md.Sum(nil))
			addOne(data, hd.seedLength)
			md.Reset()
		}
	}
	hd.addH()
	hd.addC()
	hd.addReseedCounter()

	hd.reseedCounter++
	return nil
}

func (hd *Hash) derive(seedMaterial []byte, len int) []byte {
	md := hd.newHash()
	limit := uint64(len+hd.hashSize-1) / uint64(hd.hashSize)
	var requireBytes [4]byte
	binary.BigEndian.PutUint32(requireBytes[:], uint32(len<<3))
	var ct byte = 1
	k := make([]byte, len)
	for i := 0; i < int(limit); i++ {
		md.Write([]byte{ct})
		md.Write(requireBytes[:])
		md.Write(seedMaterial)
		copy(k[i*md.Size():], md.Sum(nil))
		ct++
		md.Reset()
	}
	return k
}
