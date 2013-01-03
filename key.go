package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"time"
)

var errKeyLen = errors.New("fernet: key decodes to wrong size")

type Key [32]byte

// Decodes a base64-encoded key from s and returns it.
func DecodeKey(s string) (*Key, error) {
	var k Key
	var b [(len(k) + 2) / 3 * 3]byte
	if n := encoding.DecodedLen(len(s)); n != len(b) {
		return nil, errKeyLen
	}
	n, err := encoding.Decode(b[:], []byte(s))
	if err != nil {
		return nil, err
	}
	if n != len(k) {
		return nil, errKeyLen
	}
	copy(k[:], b[:])
	return &k, nil
}

// Must is a helper that wraps a call to a function returning (*Key, error)
// and panics if the error is non-nil. It is intended for use in variable
// initializations such as
//	var t = fernet.Must(fernet.DecodeKey("somekey"))
func Must(k *Key, err error) *Key {
	if err != nil {
		panic(err)
	}
	return k
}

// Generates a pseudorandom key using package crypto/rand.
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

// Returns the base64 encoding of k.
func (k *Key) Encode() string {
	b := make([]byte, encoding.EncodedLen(len(k)))
	encoding.Encode(b, k[:])
	return string(b)
}

// Encrypts and signs msg with key k and returns the resulting fernet token.
func (k *Key) EncryptAndSign(msg []byte) (tok []byte, err error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return gen(msg, iv, time.Now(), k)
}

// Verifies that tok is a valid fernet token that was signed at most ttl time
// ago, and returns the decrypted plaintext message contained in it.
//
// Returns nil if tok is invalid.
func (k *Key) VerifyAndDecrypt(tok []byte, ttl time.Duration) (msg []byte) {
	if !bytes.Contains(tok, pipe) {
		return jsonVerify(tok, ttl, time.Now(), k)
	}
	return verify(tok, ttl, time.Now(), k)
}
