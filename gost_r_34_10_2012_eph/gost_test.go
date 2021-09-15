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
		t.Errorf("test failed: new priv key (1)")
		return
	}
	priv1, err = LoadPrivKey(priv1.Bytes())
	if err != nil {
		t.Errorf("test failed: load priv key (1)")
		return
	}

	priv2, err := NewPrivKey(K256)
	if err != nil {
		t.Errorf("test failed: new priv key (2)")
		return
	}
	priv2, err = LoadPrivKey(priv2.Bytes())
	if err != nil {
		t.Errorf("test failed: load priv key (2)")
		return
	}

	pub1 := priv1.PubKey()
	pub1, err = LoadPubKey(pub1.Bytes())
	if err != nil {
		t.Errorf("test failed: load pub key (1)")
		return
	}

	pub2 := priv2.PubKey()
	pub2, err = LoadPubKey(pub2.Bytes())
	if err != nil {
		t.Errorf("test failed: load pub key (2)")
		return
	}

	xchkey1 := priv1.Secret(pub2)
	xchkey2 := priv2.Secret(pub1)

	if !bytes.Equal(xchkey1, xchkey2) {
		t.Errorf("test failed: secret not equal (1)")
	}

	//-----------------------------------------------------------------
	priv3, err := NewPrivKey(K256)
	if err != nil {
		t.Errorf("test failed: new priv key (3)")
		return
	}
	priv3, err = LoadPrivKey(priv3.Bytes())
	if err != nil {
		t.Errorf("test failed: load priv key (2)")
		return
	}

	pub3 := priv3.PubKey()
	pub3, err = LoadPubKey(pub3.Bytes())
	if err != nil {
		t.Errorf("test failed: load pub key (3)")
		return
	}

	xchkey3 := priv1.Secret(pub3)
	xchkey4 := priv3.Secret(pub1)

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
