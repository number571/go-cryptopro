// ГОСТ Р 34.12-2015
// https://docs.cntd.ru/document/1200121983
package gost_r_34_12_2015

/*
#include "gost.h"
*/
import "C"
import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"unsafe"

	ghash "bitbucket.org/number571/go-cryptopro/gost_r_34_11_2012"
)

var (
	_ cipher.AEAD = &Cipher{}
)

const (
	CipherType = "ГОСТ Р 34.12-2015"
)

const (
	KeySize   = 32
	BlockSize = 16
	NonceSize = 16
	Overhead  = ghash.Size256
)

/*
 * CIPHER
 */

type Cipher struct {
	key [KeySize]byte
}

// Mac-then-encrypt
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("error: key length != %d", KeySize)
	}
	cphr := new(Cipher)
	copy(cphr.key[:], key)
	return cphr, nil
}

// Encrypt with authentication information.
func (cphr *Cipher) Seal(dst, nonce, plaintext, addData []byte) []byte {
	if len(nonce) != cphr.NonceSize() {
		return nil
	}
	mbytes := bytes.Join(
		[][]byte{
			nonce,
			plaintext,
			addData,
		},
		[]byte{},
	)
	mac := ghash.SumHMAC(ghash.H256, mbytes, cphr.key[:])
	ciphertext := bytes.Join(
		[][]byte{
			mac,
			encrypt(plaintext, cphr.key[:], nonce),
		},
		[]byte{},
	)
	copy(dst[:cap(dst)], ciphertext)
	return ciphertext
}

// Decrypt with authentication information.
func (cphr *Cipher) Open(dst, nonce, ciphertext, addData []byte) ([]byte, error) {
	if len(nonce) != cphr.NonceSize() {
		return nil, fmt.Errorf("error: nonce size < nonce const")
	}
	if len(ciphertext) < Overhead {
		return nil, fmt.Errorf("error: len cipher < overhead")
	}
	mac := ciphertext[:ghash.Size256]
	plaintext := encrypt(ciphertext[ghash.Size256:], cphr.key[:], nonce)
	if plaintext == nil {
		return nil, fmt.Errorf("error: decrypt")
	}
	mbytes := bytes.Join(
		[][]byte{
			nonce,
			plaintext,
			addData,
		},
		[]byte{},
	)
	check := ghash.SumHMAC(ghash.H256, mbytes, cphr.key[:])
	if !bytes.Equal(mac, check) {
		return nil, fmt.Errorf("error: authentication")
	}
	copy(dst[:cap(dst)], plaintext)
	return plaintext, nil
}

func (cphr *Cipher) NonceSize() int {
	return NonceSize
}

func (cphr *Cipher) Overhead() int {
	return Overhead
}

func encrypt(data, key, iv []byte) []byte {
	var (
		datlen = len(data)
		cpdata = make([]byte, datlen)
	)
	copy(cpdata, data)
	var (
		datptr = toCbytes(cpdata)
		vecptr = toCbytes(iv)
		keyptr = toCbytes(key)
	)
	reslen := C.Encrypt(datptr, (C.uint)(datlen), keyptr, (C.uint)(len(key)), vecptr)
	if reslen < 0 {
		panic(fmt.Errorf("error code: %d", reslen))
	}
	return C.GoBytes(unsafe.Pointer(datptr), reslen)
}
