/*
func GenPrivKey(cfg *Config) error {}
func NewPrivKey(cfg *Config) (PrivKey, error) {}
func LoadPrivKey(pbytes []byte) (PrivKey, error) {}
func (key PrivKey) Bytes() []byte {}
func (key PrivKey) String() string {}
func (key PrivKey) Sign(dbytes []byte) ([]byte, error) {}
func (key PrivKey) PubKey() PubKey {}
func (key PrivKey) Equals(cmp PrivKey) bool {}
func (key PrivKey) Type() string {}

func LoadPubKey(pbytes []byte) (PubKey, error) {}
func (key PubKey) Address() Address {}
func (key PubKey) Bytes() []byte {}
func (key PubKey) String() string {}
func (key PubKey) VerifySignature(dbytes, sign []byte) bool {}
func (key PubKey) Equals(cmp PubKey) bool {}
func (key PubKey) Type() string {}

func NewBatchVerifier() BatchVerifier {}
func (b *BatchVerifier) Add(key PubKey, message, signature []byte) error {}
func (b *BatchVerifier) Verify() (bool, []bool) {}

func NewConfig(prov ProvType, subject, password string) *Config {}
*/
package gost_r_34_10_2012

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
