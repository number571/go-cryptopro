// ГОСТ Р 34.10-2012
// https://docs.cntd.ru/document/1200095034
package gost_r_34_10_2012_eph

/*
#include "gost.h"
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"

	gkeys "github.com/number571/go-cryptopro/gost_r_34_10_2012"
	ghash "github.com/number571/go-cryptopro/gost_r_34_11_2012"
)

var (
	_ PrivKey = PrivKey256{}
	_ PubKey  = PubKey256{}

	_ PrivKey = PrivKey512{}
	_ PubKey  = PubKey512{}
)

type ProvType gkeys.ProvType

const (
	K256 = ProvType(gkeys.K256)
	K512 = ProvType(gkeys.K512)
)

const (
	PrivKeySize256 = 118
	PrivKeySize512 = 153

	PubKeySize256 = gkeys.PubKeySize256
	PubKeySize512 = gkeys.PubKeySize512
)

const (
	KeyType = gkeys.KeyType + " EPH"
)

/*
 * PRIVATE KEY
 */

type PrivKey512 PrivKey256
type PrivKey256 []byte

func NewPrivKey(prov ProvType) (PrivKey, error) {
	var (
		reslen C.uint
	)

	result := C.GeneratePrivateKey(C.uchar(prov), &reslen)
	if result == nil {
		return nil, fmt.Errorf("error: new private key")
	}
	defer C.free(unsafe.Pointer(result))

	privraw := C.GoBytes(unsafe.Pointer(result), C.int(reslen))
	privraw = bytes.Join(
		[][]byte{
			[]byte{byte(prov)},
			privraw,
		},
		[]byte{},
	)

	switch prov {
	case K256:
		return PrivKey256(privraw), nil
	case K512:
		return PrivKey512(privraw), nil
	default:
		return nil, fmt.Errorf("error: undefined provider type")
	}
}

func LoadPrivKey(pbytes []byte) (PrivKey, error) {
	var (
		hProv   C.HCRYPTPROV
		hKey    C.HCRYPTKEY
		prov    ProvType
		privlen = len(pbytes)
	)

	switch privlen {
	case PrivKeySize256, PrivKeySize512:
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

	ret := C.ImportPrivateKey(C.uchar(prov), &hProv, &hKey, toCbytes(pbytes[1:]), C.uint(privlen-1))
	if ret < 0 {
		return nil, fmt.Errorf("error: private key is nil")
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	switch prov {
	case K256:
		return PrivKey256(pbytes), nil
	case K512:
		return PrivKey512(pbytes), nil
	default:
		return nil, fmt.Errorf("error: undefined provider type")
	}
}

func (key PrivKey512) Bytes() []byte {
	return PrivKey256(key).Bytes()
}
func (key PrivKey256) Bytes() []byte {
	return []byte(key)
}

func (key PrivKey512) String() string {
	return PrivKey256(key).String()
}
func (key PrivKey256) String() string {
	return fmt.Sprintf("Priv(%s){%X}", key.Type(), key.Bytes())
}

func (key PrivKey512) Secret(pub PubKey) []byte {
	return PrivKey256(key).Secret(pub)
}
func (key PrivKey256) Secret(pub PubKey) []byte {
	if key.Type() != pub.Type() {
		return nil
	}

	var (
		hProv  C.HCRYPTPROV
		hKey   C.HCRYPTKEY
		reslen C.uint
		prov   = key.prov()
	)

	ret := C.ImportPrivateKey(C.uchar(prov), &hProv, &hKey, key.bytes(), key.len())
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	result := C.SharedSessionKey(&hProv, &hKey, pub.(PubKey256).bytes(), pub.(PubKey256).len(), &reslen)
	if result == nil {
		return nil
	}

	resptr := unsafe.Pointer(result)
	defer C.free(resptr)

	return ghash.Sum(ghash.H256, C.GoBytes(resptr, C.int(reslen)))
}

func (key PrivKey512) PubKey() PubKey {
	return PrivKey256(key).PubKey()
}
func (key PrivKey256) PubKey() PubKey {
	var (
		hProv  C.HCRYPTPROV
		hKey   C.HCRYPTKEY
		publen C.uint
		pbytes *C.uchar
		prov   = key.prov()
	)

	ret := C.ImportPrivateKey(C.uchar(prov), &hProv, &hKey, key.bytes(), key.len())
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

func (key PrivKey512) Equals(cmp PrivKey) bool {
	return PrivKey256(key).Equals(cmp)
}
func (key PrivKey256) Equals(cmp PrivKey) bool {
	return bytes.Equal(key.Bytes(), cmp.Bytes())
}

func (key PrivKey512) Type() string {
	return PrivKey256(key).Type()
}
func (key PrivKey256) Type() string {
	return fmt.Sprintf("%s %s", KeyType, gkeys.ProvType(key.prov()))
}

func (key PrivKey256) prov() ProvType {
	return ProvType(key[0])
}

func (key PrivKey256) bytes() *C.uchar {
	return toCbytes(key[1:])
}

func (key PrivKey256) len() C.uint {
	return C.uint(len(key[1:]))
}

/*
 * PUBLIC KEY
 */

type PubKey512 PubKey256
type PubKey256 []byte

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
		return nil, fmt.Errorf("error: public key is nil")
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	return PubKey256(pbytes), nil
}

func (key PubKey512) Address() Address {
	return PubKey256(key).Address()
}
func (key PubKey256) Address() Address {
	return Address(ghash.Sum(ghash.H256, key.Bytes()))
}

func (key PubKey512) Bytes() []byte {
	return PubKey256(key).Bytes()
}
func (key PubKey256) Bytes() []byte {
	return []byte(key)
}

func (key PubKey512) String() string {
	return PubKey256(key).String()
}
func (key PubKey256) String() string {
	return fmt.Sprintf("Pub(%s){%X}", key.Type(), key.Bytes())
}

func (key PubKey512) Equals(cmp PubKey) bool {
	return PubKey256(key).Equals(cmp)
}
func (key PubKey256) Equals(cmp PubKey) bool {
	return bytes.Equal(key.Address(), cmp.Address())
}

func (key PubKey512) Type() string {
	return PubKey256(key).Type()
}
func (key PubKey256) Type() string {
	return fmt.Sprintf("%s %s", KeyType, gkeys.ProvType(key.prov()))
}

func (key PubKey256) prov() ProvType {
	return ProvType(key[0])
}

func (key PubKey256) bytes() *C.uchar {
	return toCbytes(key[1:])
}

func (key PubKey256) len() C.uint {
	return C.uint(len(key[1:]))
}
