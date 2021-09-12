// ГОСТ Р 34.11-2012
// https://docs.cntd.ru/document/1200095035
package gost_r_34_11_2012

/*
#include "gost.h"
*/
import "C"
import (
	"crypto/hmac"
	"fmt"
	"hash"
)

var (
	_ Hash = &Hash256{}
	_ Hash = &Hash512{}
)

type ProvType byte

const (
	H256 ProvType = 80
	H512 ProvType = 81
)

const (
	HashType = "ГОСТ Р 34.11-2012"
)

const (
	Size256   = 32
	Size512   = 64
	BlockSize = 64
)

func (h ProvType) String() string {
	switch h {
	case H256:
		return "256"
	case H512:
		return "512"
	default:
		return "???"
	}
}

func (h ProvType) Size() int {
	switch h {
	case H256:
		return Size256
	case H512:
		return Size512
	default:
		return -1
	}
}

/*
 * HASH
 */

type Hash512 Hash256
type Hash256 struct {
	prov   ProvType
	length C.uint
	states []byte
}

// Create Hash object.
func New(prov ProvType) Hash {
	var (
		hh C.HCRYPTHASH
		hp C.HCRYPTPROV

		states = make([]byte, 512)
		length C.uint
	)

	ret := C.NewHash(C.uchar(prov), &hp, &hh)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	defer C.CloseHash(&hh, &hp)

	ret = C.ReadStateHash(&hh, &hp, toCbytes(states), &length)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	switch prov {
	case H256:
		return &Hash256{
			prov:   prov,
			length: length,
			states: states,
		}
	case H512:
		return &Hash512{
			prov:   prov,
			length: length,
			states: states,
		}
	default:
		return nil
	}
}

// Writing a piece of information to the Hash object.
func (hasher *Hash512) Write(p []byte) (n int, err error) {
	return (*Hash256)(hasher).Write(p)
}
func (hasher *Hash256) Write(p []byte) (n int, err error) {
	var (
		hh C.HCRYPTHASH
		hp C.HCRYPTPROV

		datlen = len(p)
	)

	ret := C.NewHash(C.uchar(hasher.prov), &hp, &hh)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	defer C.CloseHash(&hh, &hp)

	ret = C.WriteStateHash(&hh, &hp, toCbytes(hasher.states), hasher.length)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	ret = C.WriteHash(&hh, &hp, toCbytes(p), C.uint(datlen))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	ret = C.ReadStateHash(&hh, &hp, toCbytes(hasher.states), &hasher.length)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	return datlen, nil
}

// If the interface function takes a non-zero argument,
// then there is a redirection to the Sum function.
func (hasher *Hash512) Sum(p []byte) []byte {
	return (*Hash256)(hasher).Sum(p)
}
func (hasher *Hash256) Sum(p []byte) []byte {
	var (
		hh C.HCRYPTHASH
		hp C.HCRYPTPROV

		output = make([]byte, hasher.Size())
	)

	ret := C.NewHash(C.uchar(hasher.prov), &hp, &hh)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	defer C.CloseHash(&hh, &hp)

	ret = C.WriteStateHash(&hh, &hp, toCbytes(hasher.states), hasher.length)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	ret = C.WriteHash(&hh, &hp, toCbytes(p), C.uint(len(p)))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	ret = C.ReadHash(&hh, &hp, toCbytes(output), C.uint(hasher.Size()))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	return output
}

// Clear data in Hash object.
func (hasher *Hash512) Reset() {
	*hasher = *(New(hasher.prov)).(*Hash512)
}
func (hasher *Hash256) Reset() {
	*hasher = *(New(hasher.prov)).(*Hash256)
}

// Output block size from hash function.
func (hasher *Hash512) Size() int {
	return (*Hash256)(hasher).Size()
}
func (hasher *Hash256) Size() int {
	return hasher.prov.Size()
}

// Input block size for hash function.
func (hasher *Hash512) BlockSize() int {
	return (*Hash256)(hasher).BlockSize()
}
func (hasher *Hash256) BlockSize() int {
	return BlockSize
}

// Retrieving a format string "ГОСТ Р 34.11-2012_???".
func (hasher *Hash512) Type() string {
	return (*Hash256)(hasher).Type()
}
func (hasher *Hash256) Type() string {
	return fmt.Sprintf("%s %s", HashType, hasher.prov)
}

// Computing a hash(256 or 512) at a time.
func Sum(prov ProvType, data []byte) []byte {
	hasher := New(prov)
	hasher.Write(data)
	return hasher.Sum(nil)
}

// Create Hash(HMAC) object.
func NewHMAC(prov ProvType, key []byte) Hash {
	return hmac.New(newHasher(prov), key)
}

// Computing a hmac(256 or 512) at a time.
func SumHMAC(prov ProvType, key, data []byte) []byte {
	hasher := hmac.New(newHasher(prov), key)
	hasher.Write(data)
	return hasher.Sum(nil)
}

func newHasher(prov ProvType) func() hash.Hash {
	h := func() hash.Hash {
		return New(prov)
	}
	return h
}
