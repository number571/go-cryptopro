package main

import (
	"fmt"

	grand "github.com/number571/go-cryptopro/gost_r_iso_28640_2012"
)

func main() {
	data := make([]byte, 16)
	grand.Read(data)

	fmt.Println(data)
	fmt.Println(grand.Rand(32))
}
