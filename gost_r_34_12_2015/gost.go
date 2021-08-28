// ГОСТ Р 34.12-2015, CBC-MODE
package gost_r_34_12_2015

/*
#include "gost.h"
*/
import "C"
import (
	"bytes"
	"fmt"
	"unsafe"

	rand "bitbucket.org/number571/go-cryptopro/gost_r_iso_28640_2012"
)

func Keygen() []byte {
	return rand.Rand(32)
}

func Encrypt(data, key []byte) []byte {
	var (
		iv              = rand.Rand(C.GR3412SIZ)
		keylen          = len(key)
		datlen          = len(data) + C.GR3412SIZ
		datptr          = (*C.uchar)(&(append(data, make([]byte, C.GR3412SIZ)...))[0])
		vecptr          = (*C.uchar)(&(iv)[0])
		keyptr *C.uchar = nil
	)
	if keylen > 0 {
		keyptr = (*C.uchar)(&key[0])
	}
	reslen := C.Cipher(C.ENCRYPT, datptr, (C.uint)(datlen), keyptr, (C.uint)(keylen), vecptr)
	if reslen < 0 {
		panic(fmt.Errorf("error code: %d", reslen))
	}
	return bytes.Join([][]byte{
		iv,
		C.GoBytes(unsafe.Pointer(datptr), reslen),
	}, []byte{})
}

func Decrypt(data, key []byte) ([]byte, error) {
	if len(data) < C.GR3412SIZ {
		return nil, fmt.Errorf("len(iv) < C.GR3412SIZ")
	}
	var (
		keylen          = len(key)
		datptr          = (*C.uchar)(&data[C.GR3412SIZ])
		vecptr          = (*C.uchar)(&(data[:C.GR3412SIZ])[0])
		keyptr *C.uchar = nil
	)
	if keylen > 0 {
		keyptr = (*C.uchar)(&key[0])
	}
	reslen := C.Cipher(C.DECRYPT, datptr, (C.uint)(len(data[C.GR3412SIZ:])), keyptr, (C.uint)(keylen), vecptr)
	if reslen < 0 {
		return nil, fmt.Errorf("error code: %d", reslen)
	}
	return C.GoBytes(unsafe.Pointer(datptr), reslen), nil
}
