/*
func New(prov ProvType) Hash {}
func (hasher *Hash) Write(p []byte) (n int, err error) {}
func (hasher *Hash) Sum(p []byte) []byte {}
func (hasher *Hash) Reset() {}
func (hasher *Hash) Size() int {}
func (hasher *Hash) BlockSize() int {}
func (hasher *Hash) Type() string {}

func Sum(prov ProvType, data []byte) []byte {}
func NewHMAC(prov ProvType, key []byte) Hash {}
func SumHMAC(prov ProvType, key, data []byte) []byte {}
*/
package gost_r_34_11_2012

/*
package main

import (
	"encoding/hex"
	"fmt"

	ghash "bitbucket.org/number571/go-cryptopro/gost_r_34_11_2012"
)

func main() {
	msg1 := []byte("aaa")
	msg2 := []byte("bbb")
	msg3 := []byte("aaabbb")

	hasher := ghash.New(ghash.H256)
	hasher.Write(msg3)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	hasher = ghash.New(ghash.H256)
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	fmt.Println(hex.EncodeToString(hasher.Sum(msg3)))

	data := ghash.Sum(ghash.H256, msg3)
	fmt.Println(hex.EncodeToString(data))

	hasher = ghash.New(ghash.H256)
	hasher.Write(data)
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))
}
*/
