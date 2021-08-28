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

	hasher := ghash.New()
	hasher.Write(msg3)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	hasher = ghash.New()
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	fmt.Println(hex.EncodeToString(hasher.Sum(msg3)))

	data := ghash.Sum(msg3)
	fmt.Println(hex.EncodeToString(data))

	hasher = ghash.New()
	hasher.Write(data)
	hasher.Write(msg1)
	hasher.Write(msg2)
	fmt.Println(hex.EncodeToString(hasher.Sum(nil)))

	fmt.Println(hex.EncodeToString(ghash.DoubleSum(msg3)))
}
*/
package gost_r_34_11_2012
