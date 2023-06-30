package kdf

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"io"
)

// NIST SP 800-108
type kdf struct {
	prf        hash.Hash
	fixedInput []byte
	counter    uint32
	buf        []byte
}

func New(h func() hash.Hash, secret, label, context []byte) *kdf {
	var buffy bytes.Buffer
	buffy.Write(label)
	buffy.Write([]byte{0})
	buffy.Write(context)
	return &kdf{
		prf:        hmac.New(h, secret),
		fixedInput: buffy.Bytes(),
	}
}

func (k *kdf) Read(bs []byte) (int, error) {
	origLen := len(bs)

	// Copy leftovers...
	n := copy(bs, k.buf)
	bs = bs[n:]

	// Fill the buffer...
	ko := k.buf
	for len(bs) > 0 {
		k.counter++
		k.prf.Reset()
		binary.Write(k.prf, binary.BigEndian, k.counter)
		k.prf.Write(k.fixedInput)
		ko = k.prf.Sum(ko[:0])
		n = copy(bs, ko)
		bs = bs[n:]
	}

	// Save the remainder...
	k.buf = ko[n:]
	return origLen, nil
}

var _ io.Reader = &kdf{}
