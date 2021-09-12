/*
func New(prov ProvType) Hash {}
func (hash *Hash) Write(p []byte) (n int, err error) {}
func (hash *Hash) Sum(p []byte) []byte {}
func (hash *Hash) Reset() {}
func (hash *Hash) Size() int {}
func (hash *Hash) BlockSize() int {}
func (hash *Hash) Type() string {}

func Sum256(data []byte) []byte {}
func Sum512(data []byte) []byte {}
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

	data := ghash.Sum256(msg3)
	fmt.Println(hex.EncodeToString(data))

	hasher = ghash.New(ghash.H256)
	hasher.Write(data)
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))
}
*/
