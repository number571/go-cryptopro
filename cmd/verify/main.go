// go run main.go 5006200000492e00004d41473100020000301306072a85030202230106082a85030701010202dcac377208e5f6c4ae42ab1ce1f97da514884b8fd8a8a7eaa7ba1fb74f8112c3b0d1f8a50225f766ba8bbbf32e26d38bc3368224e1e722640e028b087c924d9d 9c06ef2ace8186d7fe030734a2b1f56e60efdc75f09dcf5c7873b147e366a67dc8fd87f06e350706a6d37375ea7beca6a39684f31e79715fbed34bc08dd2f421 "hello, world!"
// cat test.txt | go run main.go 5006200000492e00004d41473100020000301306072a85030202230106082a85030701010202dcac377208e5f6c4ae42ab1ce1f97da514884b8fd8a8a7eaa7ba1fb74f8112c3b0d1f8a50225f766ba8bbbf32e26d38bc3368224e1e722640e028b087c924d9d 9c06ef2ace8186d7fe030734a2b1f56e60efdc75f09dcf5c7873b147e366a67dc8fd87f06e350706a6d37375ea7beca6a39684f31e79715fbed34bc08dd2f421
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
// > verify public_key signature [original_message]
// # where original message can be read from stdio.
func main() {
	var (
		data = make([]byte, 2048)
		hash = make([]byte, ghash.Size256)
		sign = make([]byte, gkeys.SignatureSize256)
	)

	switch len(os.Args) {
	case 1:
		fmt.Println("error: key undefined")
		os.Exit(1)
	case 2:
		fmt.Println("error: sign undefined")
		os.Exit(2)
	}

	pub, err := gkeys.LoadPubKey(decodeHex(os.Args[1]))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(3)
	}

	sign = decodeHex(os.Args[2])

	if len(os.Args) > 3 {
		data = []byte(strings.Join(os.Args[3:], " "))
		hash = ghash.Sum(ghash.H256, data)
		fmt.Println("Correct:", verifyHash(pub, hash, sign))
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
	fmt.Println("Correct:", verifyHash(pub, hash, sign))
}

func decodeHex(hexdata string) []byte {
	data, err := hex.DecodeString(hexdata)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(10)
	}
	return data
}

func verifyHash(pub gkeys.PubKey, hash, sign []byte) bool {
	return pub.VerifySignature(hash, sign)
}
