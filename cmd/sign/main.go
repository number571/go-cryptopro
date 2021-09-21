// go run main.go P57d32646706358da54806c1ee7a96d57eb8338a0428f6f9ef0972e46d0cb27b5557e2205e26de03ab1c370226e46b03c70c22145c0b6f0e52d93840112eefef3 "hello, world!"
// cat test.txt | go run main.go P57d32646706358da54806c1ee7a96d57eb8338a0428f6f9ef0972e46d0cb27b5557e2205e26de03ab1c370226e46b03c70c22145c0b6f0e52d93840112eefef3
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	gkeys "github.com/number571/go-cryptopro/gost_r_34_10_2012"
	ghash "github.com/number571/go-cryptopro/gost_r_34_11_2012"
)

// Example:
// > sign private_key [original_message]
// # where original message can be read from stdio.
func main() {
	var (
		data = make([]byte, 2048)
		hash = make([]byte, ghash.Size256)
		sign = make([]byte, gkeys.SignatureSize256)
	)

	if len(os.Args) == 1 {
		fmt.Println("error: key undefined")
		os.Exit(1)
	}

	priv, err := gkeys.LoadPrivKey([]byte(os.Args[1]))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

	if len(os.Args) > 2 {
		data = []byte(strings.Join(os.Args[2:], " "))
		hash = ghash.Sum(ghash.H256, data)
		sign = signHash(priv, hash)
		fmt.Println(hex.EncodeToString(sign))
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
	sign = signHash(priv, hash)
	fmt.Println(hex.EncodeToString(hash))
}

func signHash(priv gkeys.PrivKey, hash []byte) []byte {
	sign, err := priv.Sign(hash)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(10)
	}
	return sign
}
