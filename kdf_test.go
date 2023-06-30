package kdf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"testing"

	"jdtw.dev/kdf/internal/testvectors"
)

func TestBuffering(t *testing.T) {
	k := &kdf{
		buf: []byte{1, 2, 3, 4, 5, 6},
	}

	one := make([]byte, 1)
	k.Read(one)
	if one[0] != 1 {
		t.Fatalf("Expected 1; got %d", one[0])
	}

	two := make([]byte, 2)
	k.Read(two)
	if !bytes.Equal(two, []byte{2, 3}) {
		t.Fatalf("Exptected 2, 3; got %v", two)
	}

	three := make([]byte, 3)
	k.Read(three)
	if !bytes.Equal(three, []byte{4, 5, 6}) {
		t.Fatalf("Exptected 4, 5, 6; got %v", three)
	}

	if len(k.buf) != 0 {
		t.Fatal("Buffer should be empty!")
	}
}

func TestKdf(t *testing.T) {
	zeros := make([]byte, sha256.Size)
	prf := hmac.New(sha256.New, zeros)
	prf.Write([]byte{
		// Counter (big endian uint32)
		0, 0, 0, 1,
		// Label
		'l', 'a', 'b', 'e', 'l',
		// 0x00 literal
		0,
		// Context
		'c', 'o', 'n', 't', 'e', 'x', 't',
	})
	expected := prf.Sum(nil)

	kdf := New(sha256.New, zeros, []byte("label"), []byte("context"))
	// Read in two chunks to test the buffering...
	chunk1 := make([]byte, 16)
	kdf.Read(chunk1)
	chunk2 := make([]byte, 16)
	kdf.Read(chunk2)
	got := append(chunk1, chunk2...)
	if !bytes.Equal(got, expected) {
		t.Fatalf("want %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(got))
	}

	// Test with an incremented counter...
	prf.Reset()
	prf.Write([]byte{
		// Counter (big endian uint32)
		0, 0, 0, 2,
		// Label
		'l', 'a', 'b', 'e', 'l',
		// 0x00 literal
		0,
		// Context
		'c', 'o', 'n', 't', 'e', 'x', 't',
	})
	expected = prf.Sum(nil)
	kdf.Read(got)
	if !bytes.Equal(got, expected) {
		t.Fatalf("want %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(got))
	}
}

func TestNISTVectors(t *testing.T) {
	for _, tc := range testvectors.Vectors {
		t.Run(tc.Name, func(t *testing.T) {
			kdf := &kdf{
				prf:        hmac.New(tc.Hash, tc.Secret),
				fixedInput: tc.FixedInput,
			}
			got := make([]byte, len(tc.Output))
			kdf.Read(got)
			if !bytes.Equal(got, tc.Output) {
				t.Errorf("want %s, got %s", hex.EncodeToString(tc.Output), hex.EncodeToString(got))
			}
		})
	}
}
