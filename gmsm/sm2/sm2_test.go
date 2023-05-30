package sm2_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm2"
	"testing"
	"time"
)

func TestSM2(t *testing.T) {
	key, keyErr := sm2.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}

	pub := &key.PublicKey

	p, encryptErr := sm2.Encrypt(rand.Reader, pub, []byte(time.Now().String()), nil)
	if encryptErr != nil {
		t.Fatal(encryptErr)
	}
	b, decryptErr := sm2.Decrypt(key, p)
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	fmt.Println(string(b))

}

func TestNewKeyExchange(t *testing.T) {
	initiatorUID := []byte("Alice")
	responderUID := []byte("Bob")
	kenLen := 48

	key1, key1Err := sm2.GenerateKey(rand.Reader)
	if key1Err != nil {
		t.Fatal(key1Err)
	}
	pub1 := &key1.PublicKey
	key2, key2Err := sm2.GenerateKey(rand.Reader)
	if key2Err != nil {
		t.Fatal(key2Err)
	}
	pub2 := &key2.PublicKey

	initiator, err := sm2.NewKeyExchange(key1, pub2, initiatorUID, responderUID, kenLen, true)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := sm2.NewKeyExchange(key2, pub1, responderUID, initiatorUID, kenLen, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()

	rA, rAErr := initiator.InitKeyExchange(rand.Reader)
	if rAErr != nil {
		t.Fatal(rAErr)
	}

	rB, s2, rBErr := responder.RepondKeyExchange(rand.Reader, rA)
	if rBErr != nil {
		t.Fatal(rBErr)
	}

	skey1, s1, err := initiator.ConfirmResponder(rB, s2)
	if err != nil {
		t.Fatal(err)
	}
	skey2, err := responder.ConfirmInitiator(s1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skey1, skey2) {
		t.Errorf("got different key")
	}
}
