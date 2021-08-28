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

type PubKey interface {
	Address() Address
	Bytes() []byte
	String() string // <- add
	VerifySignature(msg []byte, sig []byte) bool
	Equals(PubKey) bool
	Type() string
}

type PrivKey interface {
	Bytes() []byte
	String() string // <- add
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
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
	prov     ProvType
	subject  string
	password string
}

func NewConfig(prov ProvType, subject, password string) *Config {
	switch prov {
	case K256, K512:
		return (&Config{
			prov:     prov,
			subject:  subject,
			password: password,
		}).cleanCharacters()
	default:
		return nil
	}
}

func (cfg *Config) cleanCharacters() *Config {
	cfg.subject = deleteCharacters(cfg.subject, ",\"")
	cfg.password = deleteCharacters(cfg.password, "\"")
	return cfg
}

func deleteCharacters(str, chs string) string {
	for _, ch := range chs {
		str = strings.ReplaceAll(str, string(ch), "")
	}
	return str
}

func hashString(data string) string {
	return hex.EncodeToString(ghash.Sum([]byte(data)))
}

func containerName(prov ProvType, nsubject string) string {
	return hashString(nsubject + prov.String())
}

func toGOstring(cstr *C.uchar) string {
	return C.GoString((*C.char)(unsafe.Pointer(cstr)))
}

func toCstring(gostr string) *C.uchar {
	return (*C.uchar)(&append([]byte(gostr), 0)[0])
}
