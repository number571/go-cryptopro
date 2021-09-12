// ГОСТ Р 34.10-2012
// https://docs.cntd.ru/document/1200095034
package gost_r_34_10_2012

/*
#include "gost.h"
*/
import "C"
import (
	"bytes"
	"fmt"
	"unsafe"

	ghash "bitbucket.org/number571/go-cryptopro/gost_r_34_11_2012"
)

func init() {
	GenPrivKey(&Config{
		prov:      K256,
		container: "init",
		password:  "init",
	})
}

var (
	_ PrivKey = PrivKey512{}
	_ PubKey  = PubKey512{}

	_ PrivKey = PrivKey256{}
	_ PubKey  = PubKey256{}

	_ BatchVerifier = &BatchVerifierX{}
)

type ProvType byte

const (
	K256 ProvType = 80
	K512 ProvType = 81
)

const (
	KeyType = "ГОСТ Р 34.10-2012"
)

const (
	HexHashLen = ghash.Size256 * 2

	ProvLen      = 1
	ContainerLen = HexHashLen
	PasswordLen  = HexHashLen

	PubKeySize256 = 102
	PubKeySize512 = 168

	// 1 + 64 + 64 = 129B
	PrivKeySize256 = ProvLen + ContainerLen + PasswordLen
	PrivKeySize512 = PrivKeySize256

	SignatureSize256 = 64
	SignatureSize512 = 128
)

func (k ProvType) String() string {
	switch k {
	case K256:
		return "256"
	case K512:
		return "512"
	default:
		return "???"
	}
}

/*
 * PRIVATE KEY
 */

// []byte = {1: prov, 64: container, 64: password}
type PrivKey512 PrivKey256
type PrivKey256 []byte

// Creation of a container with a binding to a password
// and generation of a private key.
func GenPrivKey(cfg *Config) error {
	ret := C.CreateContainer(
		C.uchar(cfg.prov),
		toCstring(cfg.container),
		toCstring(cfg.password),
	)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	if ret > 0 {
		return fmt.Errorf("key already exists")
	}
	return nil
}

// Getting the private key interface
// from the container name and password.
func NewPrivKey(cfg *Config) (PrivKey, error) {
	ret := C.CheckContainer(
		C.uchar(cfg.prov),
		toCstring(cfg.container),
		toCstring(cfg.password),
	)
	if ret < 0 {
		return nil, fmt.Errorf("error: private key is nil")
	}

	switch cfg.prov {
	case K256:
		return PrivKey256(bytes.Join(
			[][]byte{
				[]byte{byte(K256)},
				[]byte(cfg.container),
				[]byte(cfg.password),
			},
			[]byte{},
		)), nil
	case K512:
		return PrivKey512(bytes.Join(
			[][]byte{
				[]byte{byte(K512)},
				[]byte(cfg.container),
				[]byte(cfg.password),
			},
			[]byte{},
		)), nil
	default:
		return nil, fmt.Errorf("error: key size not in (256, 512)")
	}
}

// Getting the private key interface from bytes
// (provider_type || container_name || container_password),
// where
// sizeof(provider_type) = 1 byte,
// sizeof(container_name) = 64 byte,
// sizeof(container_password) = 64 byte.
func LoadPrivKey(pbytes []byte) (PrivKey, error) {
	var (
		prov    ProvType
		privlen = len(pbytes)
	)

	switch privlen {
	case PrivKeySize256:
		// case PrivKeySize512:
		// pass
	default:
		return nil, fmt.Errorf("error: length of private key")
	}

	prov = ProvType(pbytes[0])
	switch prov {
	case K256, K512:
		// pass
	default:
		return nil, fmt.Errorf("error: read prov type")
	}

	ret := C.CheckContainer(
		C.uchar(prov),
		toCstring(string(pbytes[1:ContainerLen+1])),
		toCstring(string(pbytes[ContainerLen+1:])),
	)

	if ret < 0 {
		return nil, fmt.Errorf("error: private key is nil")
	}

	switch prov {
	case K256:
		return PrivKey256(pbytes), nil
	case K512:
		return PrivKey512(pbytes), nil
	default:
		return nil, fmt.Errorf("error: key size not in (256, 512)")
	}
}

// Retrieving bytes (provider_type || container_name || container_password)
// from the private key interface.
func (key PrivKey512) Bytes() []byte {
	return PrivKey256(key).Bytes()
}
func (key PrivKey256) Bytes() []byte {
	return []byte(key)
}

// Translating the PrivKey interface into a string of the form
// "Priv(ГОСТ Р 34.10-2012_???)(container_name container_password)".
func (key PrivKey512) String() string {
	return PrivKey256(key).String()
}
func (key PrivKey256) String() string {
	return fmt.Sprintf("Priv(%s){%s %s}",
		key.Type(),
		toGOstring(key.container()),
		toGOstring(key.password()),
	)
}

// Signing information using the private key interface.
func (key PrivKey512) Sign(dbytes []byte) ([]byte, error) {
	return PrivKey256(key).Sign(dbytes)
}
func (key PrivKey256) Sign(dbytes []byte) ([]byte, error) {
	var (
		datlen = len(dbytes)
		reslen C.uint
	)

	result := C.SignMessage(
		C.uchar(key.prov()),
		key.container(),
		key.password(),
		toCbytes(dbytes),
		C.uint(datlen),
		&reslen,
	)
	if result == nil {
		return nil, fmt.Errorf("error: sign is nil")
	}

	resptr := unsafe.Pointer(result)
	defer C.free(resptr)

	return C.GoBytes(resptr, C.int(reslen)), nil
}

// Getting the public key interface
// from the private key interface.
func (key PrivKey512) PubKey() PubKey {
	return PrivKey256(key).PubKey()
}
func (key PrivKey256) PubKey() PubKey {
	var (
		hProv  C.HCRYPTPROV
		hKey   C.HCRYPTKEY
		publen C.uint
		pbytes *C.uchar
	)

	ret := C.OpenContainer(
		C.uchar(key.prov()),
		&hProv,
		&hKey,
		key.container(),
		key.password(),
	)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	pbytes = C.BytesPublicKey(&hKey, &publen)
	if pbytes == nil {
		panic(fmt.Errorf("error: public key is nil"))
	}
	defer C.free(unsafe.Pointer(pbytes))

	pubraw := C.GoBytes(unsafe.Pointer(pbytes), C.int(publen))
	pubraw = bytes.Join(
		[][]byte{
			[]byte{byte(key.prov())},
			pubraw,
		},
		[]byte{},
	)

	pubkey, err := LoadPubKey(pubraw)
	if err != nil {
		panic(err)
	}

	return pubkey
}

// Comparison of private keys by bytes
// (provider_type || container_name || container_password).
func (key PrivKey512) Equals(cmp PrivKey) bool {
	return PrivKey256(key).Equals(cmp)
}
func (key PrivKey256) Equals(cmp PrivKey) bool {
	return bytes.Equal(key.Bytes(), cmp.Bytes())
}

// Retrieving a format string "ГОСТ Р 34.10-2012_???".
func (key PrivKey512) Type() string {
	return PrivKey256(key).Type()
}
func (key PrivKey256) Type() string {
	return fmt.Sprintf("%s %s", KeyType, key.prov())
}

// First byte of the private key:
// 80 - ГОСТ Р 34.10-2012 256,
// 81 - ГОСТ Р 34.10-2012 512.
func (key PrivKey256) prov() ProvType {
	return ProvType(key[0])
}

// Container name in bytes.
func (key PrivKey256) container() *C.uchar {
	return toCstring(string(key[1 : ContainerLen+1]))
}

// Container password in bytes.
func (key PrivKey256) password() *C.uchar {
	return toCstring(string(key[ContainerLen+1:]))
}

/*
 * PUBLIC KEY
 */

// []byte = {1: prov, N: bytes}
type PubKey512 PubKey256
type PubKey256 []byte

// Checking the correctness of the public key bytes.
// Translating bytes into PubKey interface.
func LoadPubKey(pbytes []byte) (PubKey, error) {
	var (
		hProv  C.HCRYPTPROV
		hKey   C.HCRYPTKEY
		prov   ProvType
		publen = len(pbytes)
	)

	switch publen {
	case PubKeySize256, PubKeySize512:
		// pass
	default:
		return nil, fmt.Errorf("error: length of public key")
	}

	prov = ProvType(pbytes[0])
	switch prov {
	case K256, K512:
		// pass
	default:
		return nil, fmt.Errorf("error: read prov type")
	}

	ret := C.ImportPublicKey(C.uchar(prov), &hProv, &hKey, toCbytes(pbytes[1:]), C.uint(publen-1))
	if ret < 0 {
		return nil, fmt.Errorf("error: read public key")
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	switch prov {
	case K256:
		return PubKey256(pbytes), nil
	case K512:
		return PubKey512(pbytes), nil
	default:
		return nil, fmt.Errorf("error: undefined provider type")
	}
}

// Address - hash from the bytes of the public key.
func (key PubKey512) Address() Address {
	return PubKey256(key).Address()
}
func (key PubKey256) Address() Address {
	return Address(ghash.Sum(ghash.H256, key.Bytes()))
}

// Translating PubKey interface to bytes.
func (key PubKey512) Bytes() []byte {
	return PubKey256(key).Bytes()
}
func (key PubKey256) Bytes() []byte {
	return []byte(key)
}

// Translating the PubKey interface to a string of the form
// "Pub(ГОСТ Р 34.10-2012_???){hex_bytes}".
func (key PubKey512) String() string {
	return PubKey256(key).String()
}
func (key PubKey256) String() string {
	return fmt.Sprintf("Pub(%s){%X}", key.Type(), key.Bytes())
}

// Signature confirmation using the original data.
func (key PubKey512) VerifySignature(dbytes, sign []byte) bool {
	return PubKey256(key).VerifySignature(dbytes, sign)
}
func (key PubKey256) VerifySignature(dbytes, sign []byte) bool {
	var (
		hProv C.HCRYPTPROV
		hKey  C.HCRYPTKEY
	)

	ret := C.ImportPublicKey(C.uchar(key.prov()), &hProv, &hKey, key.bytes(), key.len())
	if ret < 0 {
		panic(fmt.Errorf("error: code: %d", ret))
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	ret = C.VerifySign(
		C.uchar(key.prov()),
		&hKey, toCbytes(sign),
		C.uint(len(sign)),
		toCbytes(dbytes),
		C.uint(len(dbytes)),
	)
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	return ret == 0
}

// Comparison of public keys by addresses.
func (key PubKey512) Equals(cmp PubKey) bool {
	return PubKey256(key).Equals(cmp)
}
func (key PubKey256) Equals(cmp PubKey) bool {
	return bytes.Equal(key.Address(), cmp.Address())
}

// Retrieving a format string "ГОСТ Р 34.10-2012_???".
func (key PubKey512) Type() string {
	return PubKey256(key).Type()
}
func (key PubKey256) Type() string {
	return fmt.Sprintf("%s %s", KeyType, key.prov())
}

// First byte of the public key:
// 80 - ГОСТ Р 34.10-2012 256,
// 81 - ГОСТ Р 34.10-2012 512.
func (key PubKey256) prov() ProvType {
	return ProvType(key[0])
}

// The main bytes of the public key.
func (key PubKey256) bytes() *C.uchar {
	return (*C.uchar)(&key[1])
}

// The length of main bytes of the public key.
func (key PubKey256) len() C.uint {
	return C.uint(len(key[1:]))
}

/*
 * BATCH VERIFIER
 */

type trySign struct {
	pubkey    PubKey
	message   []byte
	signature []byte
}

// A structure that stores several signatures
// with the subsequent possibility of checking
// the entire list for correctness.
type BatchVerifierX struct {
	signs []trySign
}

// Create Verifier.
func NewBatchVerifier() BatchVerifier {
	return &BatchVerifierX{}
}

// Add a public key, data and a signature
// for this data to the verifier object.
func (b *BatchVerifierX) Add(key PubKey, message, signature []byte) error {
	b.signs = append(b.signs, trySign{
		pubkey:    key,
		message:   message,
		signature: signature,
	})
	return nil
}

// Checking the entire list of signatures .
func (b *BatchVerifierX) Verify() (bool, []bool) {
	var (
		res  = true
		list []bool
	)
	for _, v := range b.signs {
		ok := v.pubkey.VerifySignature(v.message, v.signature)
		if !ok {
			res = false
		}
		list = append(list, ok)
	}
	return res, list
}
