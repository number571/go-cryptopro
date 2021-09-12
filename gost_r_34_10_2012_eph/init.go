package gost_r_34_10_2012_eph

/*
#cgo LDFLAGS: -Wl,--allow-multiple-definition
#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=8
#cgo linux,386 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=4
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo windows CFLAGS: -I/opt/cprocsp/include/cpcsp
#cgo windows LDFLAGS: -lcrypt32 -lpthread
*/
import "C"

type Address []byte

type PrivKey interface {
	Bytes() []byte
	String() string
	Secret(PubKey) []byte
	PubKey() PubKey
	Equals(PrivKey) bool
	Type() string
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	String() string
	Equals(PubKey) bool
	Type() string
}

func toCbytes(data []byte) *C.uchar {
	if len(data) > 0 {
		return (*C.uchar)(&data[0])
	}
	return nil
}
