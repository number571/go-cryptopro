/*
package main

import (
	"bytes"
	"fmt"

	gcipher "bitbucket.org/number571/go-cryptopro/gost_r_34_12_2015"
)

func main() {
	var (
		data = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		key  = gcipher.Keygen()
	)

	fmt.Println(data)

	enc := gcipher.Encrypt(data, key)
	fmt.Println(enc)

	dec, err := gcipher.Decrypt(enc, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(dec)

	fmt.Println(bytes.Equal(data, dec))
}
*/
package gost_r_34_12_2015
