package sm2_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"testing"
)

func TestEncode(t *testing.T) {
	pri, priErr := sm2.GenerateKey(rand.Reader)
	if priErr != nil {
		t.Error(priErr)
		return
	}
	pub := &pri.PublicKey
	pubPEM, pubPEMErr := pub.Encode()
	if pubPEMErr != nil {
		t.Error(pubPEMErr)
		return
	}
	fmt.Println(string(pubPEM))
	priPEM, priPEMErr := pri.Encode()
	if priPEMErr != nil {
		t.Error(priPEMErr)
		return
	}
	fmt.Println(string(priPEM))
	pri, priErr = sm2.ParsePrivateKey(priPEM)
	if priErr != nil {
		t.Error(priErr)
		return
	}
	pub, priErr = sm2.ParsePublicKey(pubPEM)
	if priErr != nil {
		t.Error(priErr)
		return
	}
}

func TestExchange(t *testing.T) {
	priA, priAErr := sm2.GenerateKey(rand.Reader)
	if priAErr != nil {
		t.Error(priAErr)
		return
	}
	priB, priBErr := sm2.GenerateKey(rand.Reader)
	if priBErr != nil {
		t.Error(priBErr)
		return
	}
	initiator := []byte("A")
	responder := []byte("B")
	ssa, ssas1, ssas2, ssaErr := priA.Exchange(initiator, responder, &priB.PublicKey, 16, true)
	if ssaErr != nil {
		t.Error(ssaErr)
		return
	}
	ssb, ssbs1, ssbs2, ssbErr := priB.Exchange(initiator, responder, &priA.PublicKey, 16, false)
	if ssaErr != nil {
		t.Error(ssaErr)
		return
	}
	if ssbErr != nil {
		t.Error(ssbErr)
		return
	}
	fmt.Println(bytes.Compare(ssa, ssb) == 0, bytes.Compare(ssas1, ssbs1) == 0, bytes.Compare(ssas2, ssbs2) == 0)
	fmt.Println(len(ssa), base64.StdEncoding.EncodeToString(ssa))
	fmt.Println(base64.StdEncoding.EncodeToString(ssas1))
	fmt.Println(base64.StdEncoding.EncodeToString(ssas2))
}
