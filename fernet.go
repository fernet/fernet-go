// Package fernet takes a user-provided message (an arbitrary
// sequence of bytes), a key (256 bits), and the current time,
// and produces a token, which contains the message in a form
// that can't be read or altered without the key.
//
// For more information and background, see the Fernet spec
// at https://github.com/fernet/spec.
//
// Subdirectories in this package provide command-line tools
// for working with Fernet keys and tokens.
package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"
	"io/ioutil"
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
	ts := time.Unix(int64(binary.BigEndian.Uint64(tok[1:])), 0)
	if now.After(ts.Add(ttl)) || ts.After(now.Add(maxClockSkew)) {
		return nil
	}
	n := len(tok) - sha256.Size
	var hmac [sha256.Size]byte
	genhmac(hmac[:0], tok[:n], k.signBytes())
	if subtle.ConstantTimeCompare(tok[n:], hmac[:]) != 1 {
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

type reader struct {
	plain *bytes.Buffer
	ttl   time.Duration
	keys  []*Key
	r     io.Reader
	err   error
}

func (r *reader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}

	if r.plain == nil {
		cypher, err := ioutil.ReadAll(r.r)
		if err != nil {
			r.err = err
			return 0, r.err
		}
		for _, k := range r.keys {
			msg := verify(nil, cypher, r.ttl, time.Now(), k)
			if msg != nil {
				r.plain = bytes.NewBuffer(msg)
				break
			}
		}
	}

	return r.plain.Read(p)
}

func (r *reader) Reset(nr io.Reader) {
	r.plain = nil
	r.r = nr
}

func NewReader(keys []*Key, ttl time.Duration, r io.Reader) io.Reader {
	return &reader{keys: keys, ttl: ttl, r: r}
}

type writer struct {
	key    *Key
	w      io.WriteCloser
	buf    *bytes.Buffer
	err    error
	iv     []byte
	closed bool
}

func (w *writer) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}

	return w.buf.Write(p)
}

// Close closes the underlying Writer and returns its Close return value, if the Writer
// is also an io.Closer. Otherwise it returns nil.
func (w *writer) Close() error {
	if w.err != nil {
		return w.err
	}

	if w.closed {
		return nil
	}
	w.closed = true

	// Initialize IV
	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)

	b := make([]byte, encodedLen(w.buf.Len()))
	n := gen(b, w.buf.Bytes(), iv, time.Now(), w.key)

	if _, w.err = w.w.Write(b[:n]); w.err != nil {
		return w.err
	}

	return w.w.Close()
}

func (w *writer) Reset(nw io.WriteCloser) {
	w.buf = &bytes.Buffer{}
	w.w = nw
}

func NewWriter(key *Key, w io.WriteCloser) io.WriteCloser {
	return &writer{key: key, w: w, buf: &bytes.Buffer{}}
}

// Encrypts and signs msg with key k and returns the resulting
// fernet token. If msg contains text, the text should be encoded
// with UTF-8 to follow fernet convention.
func EncryptAndSign(msg []byte, k *Key) (tok []byte, err error) {
	buf := &bytes.Buffer{}
	w := NewWriter(k, base64.NewEncoder(encoding, buf))
	r := bytes.NewReader(msg)
	if _, err := io.Copy(w, r); err != nil {
		return nil, err
	}
	w.Close()
	return buf.Bytes(), nil
}

// Verifies that tok is a valid fernet token that was signed with
// a key in k at most ttl time ago. Returns the message contained
// in tok if tok is valid, otherwise nil.
func VerifyAndDecrypt(tok []byte, ttl time.Duration, k []*Key) (msg []byte) {
	r := NewReader(k, ttl, base64.NewDecoder(encoding, bytes.NewReader(tok)))
	msg, err := ioutil.ReadAll(r)
	if err != nil {
		return nil
	}
	return msg
}
