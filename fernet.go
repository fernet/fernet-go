// Package fernet generates and verifies HMAC-based authentication tokens. It
// also encrypts data, so it can be used to transmit secure messages over the
// wire.
//
// For more information and background, see the original Fernet project at
// https://github.com/hgmnz/fernet.
package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const maxClockSkew = 60 * time.Second

var encoding = base64.URLEncoding

func gen(src, iv []byte, ts time.Time, k *Key) ([]byte, error) {
	if *k == (Key{}) {
		return nil, errors.New("fernet: zero key")
	}
	var msg, tok bytes.Buffer
	binary.Write(&msg, binary.BigEndian, ts.Unix())
	msg.Write(iv)
	p := pad(src, aes.BlockSize)
	bc, _ := aes.NewCipher(k.cryptBytes())
	cipher.NewCBCEncrypter(bc, iv).CryptBlocks(p, p)
	msg.Write(p)
	tok.Write(genhmac(msg.Bytes(), k.signBytes()))
	tok.Write(msg.Bytes())
	return b64enc(tok.Bytes()), nil
}

func verify(p []byte, ttl time.Duration, now time.Time, k *Key) []byte {
	if *k == (Key{}) {
		return nil
	}
	tok := b64dec(p)
	r := bytes.NewBuffer(tok)
	var h struct {
		HMAC     [sha256.Size]byte
		IssuedAt int64
		IV       [aes.BlockSize]byte
	}
	err := binary.Read(r, binary.BigEndian, &h)
	if err != nil {
		return nil
	}
	if subtle.ConstantTimeCompare(h.HMAC[:], genhmac(tok[len(h.HMAC):], k.signBytes())) != 1 {
		return nil
	}
	ts := time.Unix(h.IssuedAt, 0)
	if now.After(ts.Add(ttl)) || ts.After(now.Add(maxClockSkew)) {
		return nil
	}
	msg := r.Bytes()
	if len(msg)%aes.BlockSize != 0 {
		return nil
	}
	bc, _ := aes.NewCipher(k.cryptBytes())
	cipher.NewCBCDecrypter(bc, h.IV[:]).CryptBlocks(msg, msg)
	return unpad(msg)
}

// Pads p to a multiple of k using PKCS #7 standard block padding.
// See http://tools.ietf.org/html/rfc5652#section-6.3.
func pad(p []byte, k int) []byte {
	q := make([]byte, len(p)/k*k+k)
	copy(q, p)
	c := byte(len(q) - len(p))
	for i := len(p); i < len(q); i++ {
		q[i] = c
	}
	return q
}

// Removes PKCS #7 standard block padding from p.
// See http://tools.ietf.org/html/rfc5652#section-6.3.
// This function is the inverse of pad.
// If the padding is not well-formed, unpad returns nil.
func unpad(p []byte) []byte {
	c := p[len(p)-1]
	for i := len(p) - int(c); i < len(p); i++ {
		if i < 0 || p[i] != c {
			return nil
		}
	}
	return p[:len(p)-int(c)]
}

func b64enc(src []byte) []byte {
	dst := make([]byte, encoding.EncodedLen(len(src)))
	encoding.Encode(dst, src)
	return dst
}

func b64dec(src []byte) []byte {
	dst := make([]byte, encoding.DecodedLen(len(src)))
	n, err := encoding.Decode(dst, src)
	if err != nil {
		return nil
	}
	return dst[:n]
}

func genhmac(p, k []byte) []byte {
	h := hmac.New(sha256.New, k)
	h.Write(p)
	return h.Sum(nil)
}
