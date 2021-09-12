// go test -v -bench=. -benchtime=100x
package gost_r_34_10_2012

import (
	"testing"
)

const (
	TEST_SUBJECT  = "subject"
	TEST_PASSWORD = "password"
)

var (
	TEST_MESSAGE_1 = []byte("hello, world!")
	TEST_MESSAGE_2 = []byte("qwerty")
	TEST_MESSAGE_3 = []byte("abcdefghijklmnopqrstuvwxyz")
)

var (
	PRIVATE_KEY PrivKey
	PUBLIC_KEY  PubKey
)

func init() {
	cfg := NewConfig(K256, TEST_SUBJECT, TEST_PASSWORD)
	err := GenPrivKey(cfg)
	if err != nil {
		println("test warning: key already exist?")
	}

	priv, err := NewPrivKey(cfg)
	if err != nil {
		panic("test failed: new priv key")
	}

	PRIVATE_KEY = priv
	PUBLIC_KEY = priv.PubKey()
}

func TestVerifySign(t *testing.T) {
	sign, err := PRIVATE_KEY.Sign(TEST_MESSAGE_1)
	if err != nil {
		t.Errorf("test failed: sign")
	}

	if !PUBLIC_KEY.VerifySignature(TEST_MESSAGE_1, sign) {
		t.Errorf("test failed: verify (1)")
	}

	sign[7] ^= byte(0x1)

	if PUBLIC_KEY.VerifySignature(TEST_MESSAGE_1, sign) {
		t.Errorf("test failed: verify (2)")
	}
}

func TestBatchVerifier(t *testing.T) {
	batchv := NewBatchVerifier()

	msgs := [][]byte{
		TEST_MESSAGE_1,
		TEST_MESSAGE_2,
		TEST_MESSAGE_3,
	}

	for _, v := range msgs {
		sign, err := PRIVATE_KEY.Sign(v)
		if err != nil {
			t.Errorf("test failed: sign")
		}
		batchv.Add(PUBLIC_KEY, v, sign)
	}

	ok, oks := batchv.Verify()
	if !ok {
		t.Errorf("test failed: batch verify")
	}

	for i, v := range oks {
		if !v {
			t.Errorf("test failed: batch verify (%d)", i)
		}
	}
}

func BenchmarkVerifySign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sign, err := PRIVATE_KEY.Sign(TEST_MESSAGE_1)
		if err != nil {
			b.Errorf("benchmark failed: sign")
			break
		}
		if !PUBLIC_KEY.VerifySignature(TEST_MESSAGE_1, sign) {
			b.Errorf("benchmark failed: verify")
			break
		}
	}
}
