package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"strconv"
	"time"
)

type Key [32]byte

// Decodes base-64 data from s into k.
func DecodeKey(s string) (*Key, error) {
	var k Key
	var b [(len(k) + 2) / 3 * 3]byte
	if encoding.DecodedLen(len(s)) != len(b) {
		return nil, keyLenError(len(s))
	}
	n, err := encoding.Decode(b[:], []byte(s))
	if err != nil {
		return nil, err
	}
	if n != len(k) {
		return nil, keyLenError(len(s))
	}
	copy(k[:], b[:])
	return &k, nil
}

// MustDecodeKey is like DecodeKey, but panics if an error occurs.
func MustDecodeKey(s string) *Key {
	k, err := DecodeKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// Generates a random key using crypto/rand.
func GenKey() (*Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

func (k *Key) cryptBytes() []byte {
	return k[len(k)/2:]
}

func (k *Key) signBytes() []byte {
	return k[:len(k)/2]
}

// Returns the base-64 encoding of k.
func (k *Key) Encode() string {
	b := make([]byte, encoding.EncodedLen(len(k)))
	encoding.Encode(b, k[:])
	return string(b)
}

// Generates an encrypted fernet token containing msg as its message.
func (k *Key) Generate(msg []byte) (tok []byte, err error) {
	if *k == (Key{}) {
		return nil, errors.New("zero key")
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return gen(msg, iv, time.Now(), k), nil
}

// Verifies that tok is a valid fernet token that was signed at most
// ttl time ago, and returns the plaintext message contained in it.
// Returns nil if tok is invalid.
func (k *Key) Verify(tok []byte, ttl time.Duration) (msg []byte) {
	if !bytes.Contains(tok, pipe) {
		return jsonVerify(tok, ttl, time.Now(), k)
	}
	return verify(tok, ttl, time.Now(), k)
}

type keyLenError int

func (n keyLenError) Error() string {
	return "fernet: key decodes to " + strconv.Itoa(int(n)) + " bytes"
}
