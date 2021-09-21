// go run main.go 32 | base64
package main

import (
	"fmt"
	"os"
	"strconv"

	grand "github.com/number571/go-cryptopro/gost_r_iso_28640_2012"
)

// Example:
// > rand [number of bytes]
func main() {
	if len(os.Args) == 1 {
		fmt.Println("error: need arg=num")
		os.Exit(1)
	}
	num, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("error: parse num")
		os.Exit(2)
	}
	fmt.Printf("%s", grand.Rand(num))
}
