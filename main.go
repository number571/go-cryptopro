package main

import (
	grand "bitbucket.org/number571/go-cryptopro/gost_r_iso_28640_2012"
)

func main() {
	data := make([]byte, 16)
	for {
		grand.Read(data)
		res := grand.Rand(32)
		_ = res
	}
}
