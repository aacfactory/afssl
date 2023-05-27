package sm4_test

import (
	"bytes"
	"fmt"
	"github.com/aacfactory/afssl/gmsm/sm4"
	"reflect"
	"testing"
)

func TestSM4(t *testing.T) {
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	ecbMsg, err := sm4.ECB(key, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
		return
	}
	fmt.Printf("ecbMsg = %x\n", ecbMsg)
	ecbDec, err := sm4.ECB(key, ecbMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("ecbDec = %x\n", ecbDec)
	cbcMsg, err := sm4.CBC(key, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcMsg = %x\n", cbcMsg)
	cbcDec, err := sm4.CBC(key, cbcMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcDec = %x\n", cbcDec)
	if !testCompare(data, cbcDec) {
		t.Errorf("sm4 self enc and dec failed")
	}

	cbcMsg, err = sm4.CFB(key, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcCFB = %x\n", cbcMsg)

	cbcCfb, err := sm4.CFB(key, cbcMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcCFB = %x\n", cbcCfb)

	cbcMsg, err = sm4.OFB(key, data, true)
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcOFB = %x\n", cbcMsg)

	cbcOfc, err := sm4.OFB(key, cbcMsg, false)
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcOFB = %x\n", cbcOfc)
}

func TestGCM(t *testing.T) {
	key := []byte("1234567890abcdef")
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	IV := make([]byte, sm4.BlockSize)
	testA := [][]byte{ // the length of the A can be random
		[]byte{},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89},
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
	}
	for _, A := range testA {
		gcmMsg, T, err := sm4.GCM(key, IV, data, A, true)
		if err != nil {
			t.Errorf("sm4 enc error:%s", err)
		}
		fmt.Printf("gcmMsg = %x\n", gcmMsg)
		gcmDec, T_, err := sm4.GCM(key, IV, gcmMsg, A, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
		}
		fmt.Printf("gcmDec = %x\n", gcmDec)
		if bytes.Compare(T, T_) == 0 {
			fmt.Println("authentication successed")
		}
		//Failed Test : if we input the different A , that will be a falied result.
		A = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}
		gcmDec, T_, err = sm4.GCM(key, IV, gcmMsg, A, false)
		if err != nil {
			t.Errorf("sm4 dec error:%s", err)
		}
		if bytes.Compare(T, T_) != 0 {
			fmt.Println("authentication failed")
		}
	}
}

func testCompare(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i, v := range key1 {
		if i == 1 {
			fmt.Println("type of v", reflect.TypeOf(v))
		}
		a := key2[i]
		if a != v {
			return false
		}
	}
	return true
}
