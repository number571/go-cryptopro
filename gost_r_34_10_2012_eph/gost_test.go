// go test -v -bench=. -benchtime=100x
package gost_r_34_10_2012_eph

import (
	"bytes"
	"testing"
)

func TestSecret(t *testing.T) {
	//-----------------------------------------------------------------
	priv1, err := NewPrivKey(K256)
	if err != nil {
		panic(err)
	}
	priv2, err := NewPrivKey(K256)
	if err != nil {
		panic(err)
	}

	xchkey1 := priv1.Secret(priv2.PubKey())
	xchkey2 := priv2.Secret(priv1.PubKey())

	if !bytes.Equal(xchkey1, xchkey2) {
		t.Errorf("test failed: secret not equal")
	}

	//-----------------------------------------------------------------
	priv3, err := NewPrivKey(K256)
	if err != nil {
		panic(err)
	}

	xchkey3 := priv1.Secret(priv3.PubKey())
	xchkey4 := priv3.Secret(priv1.PubKey())

	if !bytes.Equal(xchkey3, xchkey4) {
		t.Errorf("test failed: secret not equal (2)")
	}

	if bytes.Equal(xchkey1, xchkey3) {
		t.Errorf("test failed: difference secrets equal")
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewPrivKey(K256)
		if err != nil {
			b.Errorf("benchmark failed: new private key")
			break
		}
	}
}

func BenchmarkSecret(b *testing.B) {
	priv1, err := NewPrivKey(K256)
	if err != nil {
		b.Errorf("benchmark failed: new private key (1)")
		return
	}
	priv2, err := NewPrivKey(K256)
	if err != nil {
		b.Errorf("benchmark failed: new private key (2)")
		return
	}
	pub2 := priv2.PubKey()
	for i := 0; i < b.N; i++ {
		_ = priv1.Secret(pub2)
	}
}
