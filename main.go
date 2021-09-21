package main

import (
	"encoding/hex"
	"fmt"

	gkeys "github.com/number571/go-cryptopro/gost_r_34_10_2012"
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

	fmt.Printf("Private key: %s\n\nPublic key: %s\n",
		string(priv.Bytes()),
		hex.EncodeToString(priv.PubKey().Bytes()),
	)
}
