package tlcp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/aacfactory/afssl/gmsm/ecdh"
)

type SM2KeyAgreement interface {
	GenerateAgreementData(sponsorId []byte, keyLen int) (sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, err error)
	GenerateKey(responseId []byte, responsePubKey, responseTmpPubKey *ecdh.PublicKey) ([]byte, error)
	GenerateAgreementDataAndKey(responseId, sponsorId []byte, sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, keyLen int) (*ecdh.PublicKey, []byte, error)
}

type sm2ke struct {
	rd     io.Reader
	prv    *ecdh.PrivateKey
	keyLen int
	uid    []byte
	ePrv   *ecdh.PrivateKey
}

func newSM2KeyKE(rd io.Reader, prv *ecdh.PrivateKey) *sm2ke {
	if rd == nil {
		rd = rand.Reader
	}
	return &sm2ke{rd: rd, prv: prv}
}

func (s *sm2ke) GenerateAgreementData(sponsorId []byte, keyLen int) (sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, err error) {
	if keyLen <= 0 {
		return nil, nil, errors.New("sm2ke: invalid key length")
	}
	s.keyLen = keyLen
	s.uid = sponsorId

	sponsorPubKey = s.prv.PublicKey()
	s.ePrv, err = ecdh.P256().GenerateKey(s.rd)
	if err != nil {
		return nil, nil, err
	}
	sponsorTmpPubKey = s.ePrv.PublicKey()
	return
}

func (s *sm2ke) GenerateKey(responseId []byte, responsePubKey, responseTmpPubKey *ecdh.PublicKey) ([]byte, error) {
	if s.ePrv == nil {
		return nil, fmt.Errorf("sm2ke: should call GenerateAgreementData frist")
	}
	secret, err := s.prv.SM2MQV(s.ePrv, responsePubKey, responseTmpPubKey)
	if err != nil {
		return nil, err
	}

	sharedKey, err := secret.SM2SharedKey(false, s.keyLen, s.prv.PublicKey(), responsePubKey, s.uid, responseId)
	if err != nil {
		return nil, err
	}

	return sharedKey, nil
}

func (s *sm2ke) GenerateAgreementDataAndKey(responseId, sponsorId []byte, sponsorPubKey, sponsorTmpPubKey *ecdh.PublicKey, keyLen int) (*ecdh.PublicKey, []byte, error) {
	ePrv, err := ecdh.P256().GenerateKey(s.rd)
	if err != nil {
		return nil, nil, err
	}
	secret, err := s.prv.SM2MQV(ePrv, sponsorPubKey, sponsorTmpPubKey)
	if err != nil {
		return nil, nil, err
	}

	sharedKey, err := secret.SM2SharedKey(true, keyLen, s.prv.PublicKey(), sponsorPubKey, responseId, sponsorId)
	if err != nil {
		return nil, nil, err
	}

	return ePrv.PublicKey(), sharedKey, nil
}
