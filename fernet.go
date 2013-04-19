// Package fernet generates and verifies HMAC-based authentication tokens. It
// also encrypts data, so it can be used to transmit secure messages over the
// wire.
//
// For more information and background, see the original Fernet project at
// https://github.com/hgmnz/fernet.
package fernet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"time"
)

const (
	version      byte = 0x80
	tsOffset          = 1
	ivOffset          = tsOffset + 8
	payOffset         = ivOffset + aes.BlockSize
	overhead          = 1 + 8 + aes.BlockSize + sha256.Size // ver + ts + iv + hmac
	maxClockSkew      = 60 * time.Second
)

var encoding = base64.URLEncoding

// generates a token from msg, writes it into tok, and returns the
// number of bytes generated, which is encodedLen(msg).
// len(tok) must be >= encodedLen(len(msg))
func gen(tok, msg, iv []byte, ts time.Time, k *Key) int {
	tok[0] = version
	binary.BigEndian.PutUint64(tok[tsOffset:], uint64(ts.Unix()))
	copy(tok[ivOffset:], iv)
	p := tok[payOffset:]
	n := pad(p, msg, aes.BlockSize)
	bc, _ := aes.NewCipher(k.cryptBytes())
	cipher.NewCBCEncrypter(bc, iv).CryptBlocks(p[:n], p[:n])
	genhmac(p[n:n], tok[:payOffset+n], k.signBytes())
	return payOffset + n + sha256.Size
}

// token length for input msg of length n, not including base64
func encodedLen(n int) int {
	const k = aes.BlockSize
	return n/k*k + k + overhead
}

// max msg length for tok of length n, for binary token (no base64)
// upper bound; not exact
func decodedLen(n int) int {
	return n - overhead
}

// if msg is nil, decrypts in place and returns a slice of tok.
func verify(msg, tok []byte, ttl time.Duration, now time.Time, k *Key) []byte {
	if len(tok) < 1 || tok[0] != version {
		return nil
	}
	n := len(tok) - sha256.Size
	var hmac [sha256.Size]byte
	genhmac(hmac[:0], tok[:n], k.signBytes())
	if subtle.ConstantTimeCompare(tok[n:], hmac[:]) != 1 {
		return nil
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(tok[1:])), 0)
	if now.After(ts.Add(ttl)) || ts.After(now.Add(maxClockSkew)) {
		return nil
	}
	pay := tok[payOffset : len(tok)-sha256.Size]
	if len(pay)%aes.BlockSize != 0 {
		return nil
	}
	if msg != nil {
		copy(msg, pay)
		pay = msg
	}
	bc, _ := aes.NewCipher(k.cryptBytes())
	iv := tok[9:][:aes.BlockSize]
	cipher.NewCBCDecrypter(bc, iv).CryptBlocks(pay, pay)
	return unpad(pay)
}

// Pads p to a multiple of k using PKCS #7 standard block padding.
// See http://tools.ietf.org/html/rfc5652#section-6.3.
func pad(q, p []byte, k int) int {
	n := len(p)/k*k + k
	copy(q, p)
	c := byte(n - len(p))
	for i := len(p); i < n; i++ {
		q[i] = c
	}
	return n
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

func genhmac(q, p, k []byte) {
	h := hmac.New(sha256.New, k)
	h.Write(p)
	h.Sum(q)
}
