// go test -v -run=TestEncryptDecrypt -bench=. -benchtime=100x
package gost_r_34_12_2015

import (
	"bytes"
	"testing"
)

var (
	TEST_MESSAGE = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	SESSION_KEY  = Keygen()
)

func TestEncryptDecrypt(t *testing.T) {
	enc := Encrypt(TEST_MESSAGE, SESSION_KEY)
	dec, err := Decrypt(enc, SESSION_KEY)
	if err != nil {
		t.Errorf("test failed: decrypt")
	}
	if !bytes.Equal(TEST_MESSAGE, dec) {
		t.Errorf("test failed: data != dec")
	}
	t.Logf("test success")
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Encrypt(TEST_MESSAGE, SESSION_KEY)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		enc := Encrypt(TEST_MESSAGE, SESSION_KEY)
		dec, err := Decrypt(enc, SESSION_KEY)
		if err != nil {
			b.Errorf("benchmark failed: decrypt")
		}
		if !bytes.Equal(TEST_MESSAGE, dec) {
			b.Errorf("benchmark failed: data != dec")
		}
	}
}
