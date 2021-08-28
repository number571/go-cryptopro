// ГОСТ Р ИСО 28640-2012
package gost_r_iso_28640_2012

/*
#include "gost.h"
*/
import "C"
import (
	"fmt"
	"io"
)

type Reader struct{}

var _ io.Reader = Reader{}

func Read(p []byte) (n int, err error) {
	return io.ReadFull(Reader{}, p)
}

func (r Reader) Read(p []byte) (n int, err error) {
	n = len(p)
	copy(p, Rand(n))
	return n, nil
}

func Rand(size int) []byte {
	var (
		output = make([]byte, size)
	)
	if size <= 0 {
		panic(fmt.Errorf("error: size <= 0"))
	}
	ret := C.Rand((*C.uchar)(&output[0]), C.uint(size))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	return output
}
