package gost_r_34_10_2012

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
import (
	"encoding/hex"
	"strings"
	"unsafe"

	ghash "bitbucket.org/number571/go-cryptopro/gost_r_34_11_2012"
)

/*
 * INTERFACES
 */

type Address []byte

type PrivKey interface {
	Bytes() []byte
	String() string
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	Type() string
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	String() string
	VerifySignature(msg []byte, sig []byte) bool
	Equals(PubKey) bool
	Type() string
}

type BatchVerifier interface {
	Add(key PubKey, message, signature []byte) error
	Verify() (bool, []bool)
}

/*
 * CONFIG
 */

type Config struct {
	prov      ProvType
	container string
	password  string
}

func NewConfig(prov ProvType, container, password string) *Config {
	switch prov {
	case K256, K512:
		return (&Config{
			prov:      prov,
			container: container,
			password:  password,
		}).wrap()
	default:
		return nil
	}
}

func (cfg *Config) wrap() *Config {
	return &Config{
		prov:      cfg.prov,
		container: doubleHashString(cfg.container + string(cfg.prov)),
		password:  doubleHashString(cfg.password + cfg.container),
	}
}

func toGOstring(cstr *C.uchar) string {
	return C.GoString((*C.char)(unsafe.Pointer(cstr)))
}

func toCstring(gostr string) *C.uchar {
	return (*C.uchar)(&append([]byte(gostr), 0)[0])
}

func toCbytes(data []byte) *C.uchar {
	if len(data) > 0 {
		return (*C.uchar)(&data[0])
	}
	return nil
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
func doubleHashString(data string) string {
	return hashString(strings.Join(
		[]string{
			hashString(data),
			data,
		},
		"",
	))
}

func hashString(data string) string {
	return hex.EncodeToString(ghash.Sum(ghash.H256, []byte(data)))
}
