package fernet

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var errKeyLen = errors.New("fernet: key decodes to wrong size")

type Key [32]byte

func (k *Key) cryptBytes() []byte {
	return k[len(k)/2:]
}

func (k *Key) signBytes() []byte {
	return k[:len(k)/2]
}

// Initializes k with pseudorandom data from package crypto/rand.
func (k *Key) Generate() error {
	_, err := io.ReadFull(rand.Reader, k[:])
	return err
}

// Returns the URL-safe base64 encoding of k.
func (k *Key) Encode() string {
	return encoding.EncodeToString(k[:])
}

// Decodes a URL-safe base64-encoded key from s and returns it.
func DecodeKey(s string) (*Key, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != len(Key{}) {
		return nil, errKeyLen
	}
	k := new(Key)
	copy(k[:], b)
	return k, nil
}

// Decodes URL-safe base64-encoded keys from a and returns them.
func DecodeKeys(a ...string) ([]*Key, error) {
	var err error
	ks := make([]*Key, len(a))
	for i, s := range a {
		ks[i], err = DecodeKey(s)
		if err != nil {
			return nil, err
		}
	}
	return ks, nil
}

// MustDecodeKeys is like DecodeKeys, but panics if an error occurs.
// It simplifies safe initialization of global variables holding
// keys.
func MustDecodeKeys(a ...string) []*Key {
	k, err := DecodeKeys(a...)
	if err != nil {
		panic(err)
	}
	return k
}
