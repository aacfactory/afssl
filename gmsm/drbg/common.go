package drbg

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/aacfactory/afssl/gmsm/sm3"
	"github.com/aacfactory/afssl/gmsm/sm4"
	"hash"
	"io"
	"time"
)

const ReseedCounterIntervalLevelTest uint64 = 8
const ReseedCounterIntervalLevelTwo uint64 = 1 << 10
const ReseedCounterIntervalLevelOne uint64 = 1 << 20

const ReseedTimeIntervalLevelTest = time.Duration(6) * time.Second
const ReseedTimeIntervalLevelTwo = time.Duration(60) * time.Second
const ReseedTimeIntervalLevelOne = time.Duration(600) * time.Second

const MaxBytes = 1 << 27
const MaxBytesPerGenerate = 1 << 11

var ErrReseedRequired = errors.New("reseed required")

type SecurityLevel byte

const (
	SecurityLevelOne  SecurityLevel = 0x01
	SecurityLevelTwo  SecurityLevel = 0x02
	SecurityLevelTest SecurityLevel = 0x99
)

func NewCtrPrng(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, entropySource io.Reader, securityStrength int, gm bool, securityLevel SecurityLevel, personalization []byte) (*Prng, error) {
	prng := new(Prng)
	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}

	prng.securityStrength = selectSecurityStrength(securityStrength)
	if gm && securityStrength < 32 {
		return nil, errors.New("invalid security strength")
	}

	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	prng.impl, err = NewCTR(cipherProvider, keyLen, securityLevel, gm, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

func NewNistCtrPrng(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*Prng, error) {
	return NewCtrPrng(cipherProvider, keyLen, entropySource, securityStrength, false, securityLevel, personalization)
}

func NewGmCtrPrng(entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*Prng, error) {
	return NewCtrPrng(sm4.NewCipher, 16, entropySource, securityStrength, true, securityLevel, personalization)
}

func NewHashPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, gm bool, securityLevel SecurityLevel, personalization []byte) (*Prng, error) {
	prng := new(Prng)
	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}
	prng.securityStrength = selectSecurityStrength(securityStrength)
	if gm && securityStrength < 32 {
		return nil, errors.New("invalid security strength")
	}

	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	prng.impl, err = NewHash(newHash, securityLevel, gm, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

func NewNistHashPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*Prng, error) {
	return NewHashPrng(newHash, entropySource, securityStrength, false, securityLevel, personalization)
}

func NewGmHashPrng(entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*Prng, error) {
	return NewHashPrng(sm3.New, entropySource, securityStrength, true, securityLevel, personalization)
}

type Prng struct {
	entropySource    io.Reader
	securityStrength int
	impl             DRBG
}

func (prng *Prng) getEntropy(entropyInput []byte) error {
	n, err := prng.entropySource.Read(entropyInput)
	if err != nil {
		return err
	}
	if n != len(entropyInput) {
		return errors.New("fail to read enough entropy input")
	}
	return nil
}

func (prng *Prng) Read(data []byte) (int, error) {
	maxBytesPerRequest := prng.impl.MaxBytesPerRequest()
	total := 0

	for len(data) > 0 {
		b := data
		if len(data) > maxBytesPerRequest {
			b = data[:maxBytesPerRequest]
		}

		err := prng.impl.Generate(b, nil)
		if err == ErrReseedRequired {
			entropyInput := make([]byte, prng.securityStrength)
			err := prng.getEntropy(entropyInput)
			if err != nil {
				return 0, err
			}
			err = prng.impl.Reseed(entropyInput, nil)
			if err != nil {
				return 0, err
			}
		} else if err != nil {
			return 0, err
		}
		total += len(b)
		data = data[len(b):]
	}
	return total, nil
}

type DRBG interface {
	NeedReseed() bool
	Reseed(entropy, additional []byte) error
	Generate(b, additional []byte) error
	MaxBytesPerRequest() int
}

type Base struct {
	v                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedIntervalInTime    time.Duration
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	securityLevel           SecurityLevel
	gm                      bool
}

func (base *Base) NeedReseed() bool {
	return (base.reseedCounter > base.reseedIntervalInCounter) || (base.gm && time.Since(base.reseedTime) > base.reseedIntervalInTime)
}

func (base *Base) setSecurityLevel(securityLevel SecurityLevel) {
	base.securityLevel = securityLevel
	switch securityLevel {
	case SecurityLevelTwo:
		base.reseedIntervalInCounter = ReseedCounterIntervalLevelTwo
		base.reseedIntervalInTime = ReseedTimeIntervalLevelTwo
	case SecurityLevelTest:
		base.reseedIntervalInCounter = ReseedCounterIntervalLevelTest
		base.reseedIntervalInTime = ReseedTimeIntervalLevelTest
	default:
		base.reseedIntervalInCounter = ReseedCounterIntervalLevelOne
		base.reseedIntervalInTime = ReseedTimeIntervalLevelOne
	}
}

func selectSecurityStrength(requested int) int {
	switch {
	case requested <= 14:
		return 14
	case requested <= 16:
		return 16
	case requested <= 24:
		return 24
	case requested <= 32:
		return 32
	default:
		return requested
	}
}

func add(left, right []byte, len int) {
	var temp uint16 = 0
	for i := len - 1; i >= 0; i-- {
		temp += uint16(left[i]) + uint16(right[i])
		right[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

func addOne(data []byte, len int) {
	var temp uint16 = 1
	for i := len - 1; i >= 0; i-- {
		temp += uint16(data[i])
		data[i] = byte(temp & 0xff)
		temp >>= 8
	}
}
