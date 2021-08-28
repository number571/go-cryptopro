// ГОСТ Р 34.11-2012
package gost_r_34_11_2012

/*
#include "gost.h"
*/
import "C"
import (
	"bytes"
	"fmt"
	"hash"
)

type Hash struct {
	hHash *C.HCRYPTHASH
	hProv *C.HCRYPTPROV
}

const (
	Size      = 32
	BlockSize = 64
)

var _ hash.Hash = Hash{}

func New() Hash {
	var (
		hh C.HCRYPTHASH
		hp C.HCRYPTPROV
	)
	ret := C.NewHash(&hp, &hh)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	return Hash{
		hHash: &hh,
		hProv: &hp,
	}
}

func (h Hash) Write(p []byte) (n int, err error) {
	var (
		datlen          = len(p)
		datptr *C.uchar = nil
	)
	if datlen > 0 {
		datptr = (*C.uchar)(&p[0])
	}
	ret := C.WriteHash(h.hHash, h.hProv, datptr, C.uint(datlen))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	return datlen, nil
}

func (h Hash) Sum(b []byte) []byte {
	var (
		output = make([]byte, h.Size())
	)
	if b != nil {
		return Sum(b)
	}
	ret := C.ReadHash(h.hHash, h.hProv, (*C.uchar)(&output[0]), C.uint(h.Size()))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	C.CloseHash(h.hHash, h.hProv)
	return output
}

func (h Hash) Reset() {
	C.CloseHash(h.hHash, h.hProv)
	ret := C.NewHash(h.hHash, h.hProv)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
}

func (h Hash) Size() int {
	// 256 bits
	return Size
}

func (h Hash) BlockSize() int {
	// 512 bits
	return BlockSize
}

func Sum(data []byte) []byte {
	hasher := New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// 	BaseProblem (Iteration) =>
//	if
// 		m     = m1, m2, ..., mk
// 		m'    = m1, m2, ..., mk, m[k+1]
//		and
//		size of blocks m[i] equals size of hashing blocks
//	then
// 		H(m') = H'(H(m) || m[k+1])
//
// 	BaseProblem: Problem#1 (Addition) =>
//	if
//		h  = H(MAC || m)
// 		and
// 		h' = H'(h || m')
//	then
//		MAC is saved with message (m || m')
//
// 	BaseProblem: Problem#2 (Part collision) =>
//	if
// 		h  = H(m || MAC)
// 		h' = H(m'|| MAC)
// 		and
//		H(m) = H(m')
// 	then
//		h = h'
//
//	Solution from
//	"Practical cryptography" Niels Ferguson, Bruce Schneier
//
// 	Solution#1 (Addition) =>
//			Q(m) -> H(H(m) || m)
// 		if
// 			h  = Q(MAC || m) = H(H(MAC || m) || (MAC || m))
//			and
//			h' = H'(h || m')
// 		then
//			MAC is not saved correctly with message (m || m')
//		because
// 			H'(H(H(MAC || m) || (MAC || m)) || m')
//			not equal
//			H'(H(H(MAC || m || m') || (MAC || m || m')))
//
// 	Solution#2 (Part collision) =>
//			Q(m) -> H(H(m) || m)
//		if
//			h = Q(m || MAC)
//			and
//			h' = Q(m' || MAC)
//			and
//			H(m) = H(m')
//		then
//			h
//			not equal
//			h'
//		because
//			Q(m)
//			not equal
//			Q(m') =>
//				H(H(m) || m)
//				not equal
//				H(H(m') || m') =>
//					H(H(m || MAC) || (m || MAC))
//					not equal
//					H(H(m' || MAC) || (m' || MAC))
func DoubleSum(data []byte) []byte {
	return Sum(bytes.Join([][]byte{
		Sum(data),
		data,
	}, []byte{}))
}
