// go test -v -bench=. -benchtime=100x
package gost_r_34_11_2012

import (
	"encoding/hex"
	"testing"
)

const (
	HASH_RESULT_256 = "2e3cbeb240b4b8d1e2dc8610faff9e5bee23f95bb04c18d999034487dbecb490"
	HASH_RESULT_512 = "9d76bd134189782acae0756763c7b1c89747c264a7d0ca3c47f5402d002e02ce6fe743159e7472eaab7c5aae5bbee31316ed5acc5051a69fe6bedf50a7bf273e"
)

var (
	TEST_MESSAGE_1 = []byte("aaa")
	TEST_MESSAGE_2 = []byte("bbb")
	TEST_MESSAGE_3 = []byte("aaabbb") // <- hashing
)

func TestHash256(t *testing.T) {
	//-----------------------------------------------------------------
	hasher := New(H256)
	hasher.Write(TEST_MESSAGE_3)
	if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT_256 {
		t.Errorf("test failed: hash(1) != HASH_RESULT")
		return
	}

	if hex.EncodeToString(Sum(H256, TEST_MESSAGE_3)) != HASH_RESULT_256 {
		t.Errorf("test failed: hash(2) != HASH_RESULT")
		return
	}

	hasher = New(H256)
	hasher.Write(TEST_MESSAGE_1)
	hasher.Write(TEST_MESSAGE_2)
	if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT_256 {
		t.Errorf("test failed: hash(2) != HASH_RESULT")
		return
	}

	//-----------------------------------------------------------------
	hasher = New(H256)
	hasher.Write(TEST_MESSAGE_1)
	res1 := hex.EncodeToString(hasher.Sum(nil))

	hasher.Reset()
	hasher.Write(TEST_MESSAGE_1)
	res2 := hex.EncodeToString(hasher.Sum(nil))

	if res1 != res2 {
		t.Errorf("test failed: reset results not equals")
		return
	}
}

func TestHash512(t *testing.T) {
	//-----------------------------------------------------------------
	hasher := New(H512)
	hasher.Write(TEST_MESSAGE_3)
	if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT_512 {
		t.Errorf("test failed: hash(1) != HASH_RESULT")
		return
	}

	if hex.EncodeToString(Sum(H512, TEST_MESSAGE_3)) != HASH_RESULT_512 {
		t.Errorf("test failed: hash(2) != HASH_RESULT")
		return
	}

	hasher = New(H512)
	hasher.Write(TEST_MESSAGE_1)
	hasher.Write(TEST_MESSAGE_2)
	if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT_512 {
		t.Errorf("test failed: hash(2) != HASH_RESULT")
		return
	}

	//-----------------------------------------------------------------
	hasher = New(H512)
	hasher.Write(TEST_MESSAGE_1)
	res1 := hex.EncodeToString(hasher.Sum(nil))

	hasher.Reset()
	hasher.Write(TEST_MESSAGE_1)
	res2 := hex.EncodeToString(hasher.Sum(nil))

	if res1 != res2 {
		t.Errorf("test failed: reset results not equals")
		return
	}
}

func BenchmarkHasher256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hasher := New(H256)
		hasher.Write(TEST_MESSAGE_1)
		hasher.Write(TEST_MESSAGE_2)
		if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT_256 {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
			break
		}
	}
}

func BenchmarkSum256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		data := Sum(H256, TEST_MESSAGE_3)
		if hex.EncodeToString(data) != HASH_RESULT_256 {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
			break
		}
	}
}

func BenchmarkHasher512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hasher := New(H512)
		hasher.Write(TEST_MESSAGE_1)
		hasher.Write(TEST_MESSAGE_2)
		if hex.EncodeToString(hasher.Sum(nil)) != HASH_RESULT_512 {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
			break
		}
	}
}

func BenchmarkSum512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		data := Sum(H512, TEST_MESSAGE_3)
		if hex.EncodeToString(data) != HASH_RESULT_512 {
			b.Errorf("benchmark failed: hash != HASH_RESULT")
			break
		}
	}
}
