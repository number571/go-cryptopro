// ГОСТ Р ИСО 28640-2012
// https://docs.cntd.ru/document/1200096454
package gost_r_iso_28640_2012

/*
#include "gost.h"
*/
import "C"
import (
	"fmt"
	"io"
)

var (
	Reader io.Reader = reader{}
)

const (
	RandType = "ГОСТ Р ИСО 28640-2012"
)

type reader struct{}

// Call forwarding function
// to an interface function.
func Read(p []byte) (int, error) {
	return io.ReadFull(Reader, p)
}

// Interface function for the Reader object.
func (r reader) Read(p []byte) (int, error) {
	var (
		n   = len(p)
		res = Rand(n)
	)
	if res == nil {
		return 0, fmt.Errorf("rand is nil")
	}
	copy(p, res)
	return n, nil
}

// The CryptGenRandom function is used based on
// cryptographic provider PROV_GOST_2012_256.
func Rand(size int) []byte {
	var (
		output = make([]byte, size)
	)
	if size < 0 {
		return nil
	}
	ret := C.Rand(toCbytes(output), C.uint(size))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	return output
}
