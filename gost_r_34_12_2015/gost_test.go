// go test -v -bench=. -benchtime=100x
package gost_r_34_12_2015

import (
	"bytes"
	"testing"
)

var (
	TEST_MESSAGE = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	OPEN_MESSAGE = []byte("hello, world")
	SESSION_KEY  = []byte("qwertyuiopasdfghjklzxcvbnm123456")
	NONCE        = []byte("1234567890123456")
)

func TestEncryptDecrypt(t *testing.T) {
	aead, err := New(SESSION_KEY)
	if err != nil {
		t.Errorf("test failed: new aead error")
	}

	enc := aead.Seal(nil, NONCE, TEST_MESSAGE, OPEN_MESSAGE)

	dec, err := aead.Open(nil, NONCE, enc, OPEN_MESSAGE)
	if err != nil {
		t.Errorf("test failed: data != dec")
	}

	if !bytes.Equal(TEST_MESSAGE, dec) {
		t.Errorf("test failed: data != dec")
	}

	enc[50] ^= byte(0x1)

	_, err = aead.Open(nil, NONCE, enc, OPEN_MESSAGE)
	if err == nil {
		t.Errorf("test failed: corrupted dec = data")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	aead, err := New(SESSION_KEY)
	if err != nil {
		b.Errorf("test failed: new aead error")
	}
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(nil, NONCE, TEST_MESSAGE, OPEN_MESSAGE)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	aead, err := New(SESSION_KEY)
	if err != nil {
		b.Errorf("test failed: new aead error")
	}
	for i := 0; i < b.N; i++ {
		enc := aead.Seal(nil, NONCE, TEST_MESSAGE, OPEN_MESSAGE)
		_, err := aead.Open(nil, NONCE, enc, OPEN_MESSAGE)
		if err != nil {
			b.Errorf("test failed: data != dec")
		}
	}
}
