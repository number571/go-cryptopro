// go test -v -run=TestHash -bench=. -benchtime=100x
package gost_r_34_11_2012

import (
	"encoding/hex"
	"testing"
)

const (
	HASH_RESULT  = "2e3cbeb240b4b8d1e2dc8610faff9e5bee23f95bb04c18d999034487dbecb490"
	DHASH_RESULT = "7c8ae9a518d240d6174a18c861db7b46856de3d146766bda4447edeaf7e2ad0c"
)

var (
	TEST_MESSAGE_1 = []byte("aaa")
	TEST_MESSAGE_2 = []byte("bbb")
	TEST_MESSAGE_3 = []byte("aaabbb") // <- hashing
)

func TestHash(t *testing.T) {
	hasher := New()
	hasher.Write(TEST_MESSAGE_3)
	if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT {
		t.Errorf("test failed: hash(1) != HASH_RESULT")
	}

	hasher = New()
	hasher.Write(TEST_MESSAGE_1)
	hasher.Write(TEST_MESSAGE_2)
	if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT {
		t.Errorf("test failed: hash(2) != HASH_RESULT")
	}

	if hex.EncodeToString(hasher.Sum(TEST_MESSAGE_3)) != HASH_RESULT {
		t.Errorf("test failed: hash(3) != HASH_RESULT")
	}

	data := Sum(TEST_MESSAGE_3)

	if hex.EncodeToString(data) != HASH_RESULT {
		t.Errorf("test failed: hash(4) != HASH_RESULT")
	}

	hasher = New()
	hasher.Write(data)
	hasher.Write(TEST_MESSAGE_1)
	hasher.Write(TEST_MESSAGE_2)

	if hex.EncodeToString(hasher.Sum(nil)) != DHASH_RESULT {
		t.Errorf("test failed: hash(5) != DHASH_RESULT")
	}

	if hex.EncodeToString(DoubleSum(TEST_MESSAGE_3)) != DHASH_RESULT {
		t.Errorf("test failed: hash(6) != DHASH_RESULT")
	}

	t.Logf("test success")
}

func BenchmarkHasher(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hasher := New()
		hasher.Write(TEST_MESSAGE_1)
		hasher.Write(TEST_MESSAGE_2)
		if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
		}
	}
}

func BenchmarkSum(b *testing.B) {
	for i := 0; i < b.N; i++ {
		data := Sum(TEST_MESSAGE_3)
		if hex.EncodeToString(data) != HASH_RESULT {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
		}
	}
}

func BenchmarkDoubleSum(b *testing.B) {
	for i := 0; i < b.N; i++ {
		data := DoubleSum(TEST_MESSAGE_3)
		if hex.EncodeToString(data) != DHASH_RESULT {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
		}
	}
}
