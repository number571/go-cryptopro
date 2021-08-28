// ГОСТ Р 34.10-2012
package gost_r_34_10_2012

/*
#include "gost.h"
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"unsafe"

	ghash "bitbucket.org/number571/go-cryptopro/gost_r_34_11_2012"
)

var (
	_ PrivKey       = PrivKey512{}
	_ PrivKey       = PrivKey256{}
	_ PubKey        = PubKey512{}
	_ PubKey        = PubKey256{}
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
	HexHashLen = ghash.Size * 2

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
		return "_256"
	case K512:
		return "_512"
	default:
		return "_???"
	}
}

/*
 * PUBLIC KEY
 */

// []byte = {1: prov, N: bytes}
type PubKey512 PubKey256
type PubKey256 []byte

func LoadPubKey(pbytes []byte) (PubKey, error) {
	var (
		hProv  C.HCRYPTPROV
		hKey   C.HCRYPTKEY
		prov   ProvType
		pubptr *C.uchar
		publen = len(pbytes)
	)

	if publen < 2 {
		return PubKey256{}, fmt.Errorf("error: arg < (2 bytes)")
	}

	prov = ProvType(pbytes[0])
	pubptr = (*C.uchar)(&pbytes[1])

	ret := C.ImportPublicKey(C.uchar(prov), &hProv, &hKey, pubptr, C.uint(publen))
	if ret < 0 {
		return PubKey256{}, fmt.Errorf("error: read public key")
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
		return PubKey256{}, fmt.Errorf("error: undefined provider type")
	}
}

func (key PubKey512) Address() Address {
	return PubKey256(key).Address()
}
func (key PubKey256) Address() Address {
	return Address(ghash.Sum(key.Bytes()))
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

func (key PubKey512) VerifySignature(dbytes, sign []byte) bool {
	return PubKey256(key).VerifySignature(dbytes, sign)
}
func (key PubKey256) VerifySignature(dbytes, sign []byte) bool {
	var (
		hProv  C.HCRYPTPROV
		hKey   C.HCRYPTKEY
		datlen = len(dbytes)
		siglen = len(sign)
		datptr *C.uchar
		sigptr *C.uchar
	)

	if datlen > 0 {
		datptr = (*C.uchar)(&dbytes[0])
	}

	if siglen > 0 {
		sigptr = (*C.uchar)(&sign[0])
	}

	pbytes := key.bytes()
	ret := C.ImportPublicKey(C.uchar(key.prov()), &hProv, &hKey, (*C.uchar)(&pbytes[0]), C.uint(len(pbytes)))
	if ret < 0 {
		panic(fmt.Errorf("error: code: %d", ret))
	}
	defer func() {
		C.CryptDestroyKey(hKey)
		C.CryptReleaseContext(hProv, C.uint(0))
	}()

	ret = C.VerifySign(C.uchar(key.prov()), &hKey, sigptr, C.uint(siglen), datptr, C.uint(datlen))
	if ret < 0 {
		panic(fmt.Errorf("error code: %d", ret))
	}

	return ret == 0
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
	return fmt.Sprintf("%s%s", KeyType, key.prov())
}

func (key PubKey256) prov() ProvType {
	return ProvType(key[0])
}

func (key PubKey256) bytes() []byte {
	return key[1:]
}

/*
 * PRIVATE KEY
 */

// []byte = {1: prov, 64: container, 64: password}
type PrivKey512 PrivKey256
type PrivKey256 []byte

// TODO: refactoring
func GenPrivKey(cfg *Config) error {
	if runtime.GOOS != "linux" {
		return errors.New("error: support only linux platform")
	}
	// -createcert: create certificate request, send it to CA;
	// -provtype:
	// 	80	GOST R 34.10-2012 (256) Signature with Diffie-Hellman Key Exchange;
	// 	81	GOST R 34.10-2012 (512) Signature with Diffie-Hellman Key Exchange;
	// -rdn: CN (certificate name);
	// -cont: container's path;
	// -pin: key container password;
	// -ku: use user container (CURRENT_USER);
	// -du: install into user store (CURRENT_USER);
	// -ex: create/use exchange key;
	// -ca: specify Microsoft CA URL;
	return exec.Command(
		"sh",
		"-c",
		fmt.Sprintf(
			// -ca http://cryptopro.ru/certsrv
			"/opt/cprocsp/bin/amd64/cryptcp -creatcert -pin \"%s\" -provtype %d -rdn \"CN=%s%s\" -cont \"\\\\\\\\.\\\\HDIMAGE\\\\%s\" -ku -du -ex",
			hashString(cfg.password),
			cfg.prov,
			cfg.subject,
			cfg.prov.String(),
			containerName(cfg.prov, cfg.subject),
		),
	).Run()
}

func NewPrivKey(cfg *Config) (PrivKey, error) {
	var (
		password  = hashString(cfg.password)
		bpassword = toCstring(password)

		container  = containerName(cfg.prov, cfg.subject)
		bcontainer = toCstring(container)
	)

	ret := C.CheckPrivateKey(C.uchar(cfg.prov), bcontainer, bpassword)
	if ret < 0 {
		return PrivKey256{}, fmt.Errorf("error: private key is nil")
	}

	switch cfg.prov {
	case K256:
		return PrivKey256(bytes.Join(
			[][]byte{
				[]byte{byte(K256)},
				[]byte(container),
				[]byte(password),
			},
			[]byte{},
		)), nil
	case K512:
		return PrivKey512(bytes.Join(
			[][]byte{
				[]byte{byte(K512)},
				[]byte(container),
				[]byte(password),
			},
			[]byte{},
		)), nil
	default:
		return PrivKey256{}, fmt.Errorf("error: key size not in (256, 512)")
	}
}

func LoadPrivKey(pbytes []byte) (PrivKey, error) {
	if len(pbytes) != PrivKeySize256 {
		return nil, fmt.Errorf("error: length of private key")
	}

	var (
		prov       = ProvType(pbytes[0])
		bcontainer = toCstring(string(pbytes[1 : ContainerLen+1]))
		bpassword  = toCstring(string(pbytes[ContainerLen+1:]))
	)

	ret := C.CheckPrivateKey(C.uchar(prov), bcontainer, bpassword)
	if ret < 0 {
		return PrivKey256{}, fmt.Errorf("error: private key is nil")
	}

	switch prov {
	case K256:
		return PrivKey256(pbytes), nil
	case K512:
		return PrivKey512(pbytes), nil
	default:
		return PrivKey256{}, fmt.Errorf("error: key size not in (256, 512)")
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
	return fmt.Sprintf("Priv(%s){%s %s}",
		key.Type(),
		toGOstring(key.container()),
		toGOstring(key.password()),
	)
}

func (key PrivKey512) Sign(dbytes []byte) ([]byte, error) {
	return PrivKey256(key).Sign(dbytes)
}
func (key PrivKey256) Sign(dbytes []byte) ([]byte, error) {
	var (
		datlen = len(dbytes)
		datptr *C.uchar
		reslen C.uint
	)

	if datlen > 0 {
		datptr = (*C.uchar)(&dbytes[0])
	}

	result := C.SignMessage(
		C.uchar(key.prov()),
		key.container(),
		key.password(),
		datptr,
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

	ret := C.HcryptKey(
		C.uchar(key.prov()),
		&hProv,
		&hKey,
		key.container(),
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
	return fmt.Sprintf("%s%s", KeyType, key.prov())
}

func (key PrivKey256) prov() ProvType {
	return ProvType(key[0])
}

func (key PrivKey256) container() *C.uchar {
	return toCstring(string(key[1 : ContainerLen+1]))
}

func (key PrivKey256) password() *C.uchar {
	return toCstring(string(key[ContainerLen+1:]))
}

/*
 * BATCH VERIFIER
 */

type trySign struct {
	pubkey    PubKey
	message   []byte
	signature []byte
}

type BatchVerifierX struct {
	signs []trySign
}

func NewBatchVerifier() BatchVerifier {
	return &BatchVerifierX{}
}

func (b *BatchVerifierX) Add(key PubKey, message, signature []byte) error {
	b.signs = append(b.signs, trySign{
		pubkey:    key,
		message:   message,
		signature: signature,
	})
	return nil
}

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
