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
