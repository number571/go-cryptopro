/*
func NewPrivKey(cfg *Config) (PrivKey, error) {}
func LoadPrivKey(pbytes []byte) (PrivKey, error) {}
func (key PrivKey) Bytes() []byte {}
func (key PrivKey) String() string {}
func (key PrivKey) Secret(pub PubKey) []byte {}
func (key PrivKey) PubKey() PubKey {}
func (key PrivKey) Equals(cmp PrivKey) bool {}
func (key PrivKey) Type() string {}

func LoadPubKey(pbytes []byte) (PubKey, error) {}
func (key PubKey) Address() Address {}
func (key PubKey) Bytes() []byte {}
func (key PubKey) String() string {}
func (key PubKey) Equals(cmp PubKey) bool {}
func (key PubKey) Type() string {}
*/
package gost_r_34_10_2012_eph

/*
package main

import (
	"bytes"
	"fmt"

	gkeys "bitbucket.org/number571/go-cryptopro/gost_r_34_10_2012_eph"
)

func main() {
	priv1, err := gkeys.NewPrivKey(gkeys.K256)
	if err != nil {
		panic(err)
	}
	priv2, err := gkeys.NewPrivKey(gkeys.K256)
	if err != nil {
		panic(err)
	}

	xchkey1 := priv1.Secret(priv2.PubKey())
	xchkey2 := priv2.Secret(priv1.PubKey())

	fmt.Printf("Xchkey1: %X;\nXchkey2: %X;\nSuccess: %t;\n",
		xchkey1,
		xchkey2,
		bytes.Equal(xchkey1, xchkey2),
	)
}
*/
