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

	ghash "github.com/number571/go-cryptopro/gost_r_34_11_2012"
)

func main() {
	msg := []byte("hello, world!")

	hash := ghash.Sum(ghash.H256, msg)
	fmt.Println(hex.EncodeToString(hash))
}
*/
