/*
package main

import (
	"fmt"

	gkeys "bitbucket.org/number571/go-cryptopro/gost_r_34_10_2012"
)

func main() {
	cfg := gkeys.NewConfig(gkeys.K256, "username", "password")

	err := gkeys.GenPrivKey(cfg)
	if err != nil {
		fmt.Println("Warning: key already exist?")
	}

	priv, err := gkeys.NewPrivKey(cfg)
	if err != nil {
		panic(err)
	}

	pub := priv.PubKey()
	pbytes := pub.Bytes()

	msg := []byte("hello, world!")
	sign, err := priv.Sign(msg)
	if err != nil {
		panic(err)
	}

	fmt.Printf(
		"Type: %s;\nPubKey [%dB]: %x;\nSign [%dB]: %x;\nSuccess: %t;\n",
		pub.Type(),
		len(pbytes),
		pbytes,
		len(sign),
		sign,
		pub.VerifySignature(msg, sign),
	)
}
*/
package gost_r_34_10_2012
