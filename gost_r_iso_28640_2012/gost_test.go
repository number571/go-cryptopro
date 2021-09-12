// go test -v -bench=. -benchtime=100x
package gost_r_iso_28640_2012

import (
	"bytes"
	"testing"
)

const (
	READSIZE = 128
)

func TestRand(t *testing.T) {
	var buffer = make([]byte, READSIZE)
	n, err := Read(buffer)
	if err != nil {
		t.Errorf("test failed: err != nil")
	}
	if n != READSIZE {
		t.Errorf("test failed: n != READSIZE")
	}
	if bytes.Equal(buffer, Rand(READSIZE)) {
		t.Errorf("test failed: rand equal")
	}
}

func BenchmarkRand(b *testing.B) {
	var buffer = make([]byte, READSIZE)
	for i := 0; i < b.N; i++ {
		n, err := Read(buffer)
		if err != nil {
			b.Errorf("benchmark failed: err != nil")
		}
		if n != READSIZE {
			b.Errorf("benchmark failed: n != READSIZE")
		}
	}
}
