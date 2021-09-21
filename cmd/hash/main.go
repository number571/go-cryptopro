// go run main.go "hello, world!"
// cat test.txt | go run main.go
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	ghash "github.com/number571/go-cryptopro/gost_r_34_11_2012"
)

// Example:
// > hash [original_message]
// # where original message can be read from stdio.
func main() {
	var (
		data = make([]byte, 2048)
		hash = make([]byte, ghash.Size256)
	)

	if len(os.Args) > 1 {
		data = []byte(strings.Join(os.Args[1:], " "))
		hash = ghash.Sum(ghash.H256, data)
		fmt.Println(hex.EncodeToString(hash))
		os.Exit(0)
	}

	hasher := ghash.New(ghash.H256)
	reader := bufio.NewReader(os.Stdin)
	for {
		n, err := reader.Read(data)
		if err != nil {
			break
		}
		hasher.Write(data[:n])
	}

	hash = hasher.Sum(nil)
	fmt.Println(hex.EncodeToString(hash))
}
