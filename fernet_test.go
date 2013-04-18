package fernet

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"
	"time"
)

type test struct {
	Secret []byte
	Src    string
	IV     [aes.BlockSize]byte
	Now    time.Time
	TTLSec int `json:"ttl_sec"`
	Token  []byte
	Desc   string
}

func mustLoadTests(path string) []test {
	base64.StdEncoding = base64.URLEncoding
	var ts []test
	if f, err := os.Open(path); err != nil {
		panic(err)
	} else if err = json.NewDecoder(f).Decode(&ts); err != nil {
		panic(err)
	}
	return ts
}

func TestGenerate(t *testing.T) {
	for _, tok := range mustLoadTests("generate.json") {
		var k Key
		copy(k[:], tok.Secret)
		g := make([]byte, encodedLen(len(tok.Src)))
		n := gen(g, []byte(tok.Src), tok.IV[:], tok.Now, &k)
		if n != len(g) {
			t.Errorf("want %v, got %v", len(g), n)
		}
		if !reflect.DeepEqual(g, tok.Token) {
			t.Errorf("want %v, got %v", tok.Token, g)
			t.Log("want")
			dumpTok(t, tok.Token, len(tok.Token))
			t.Log("got")
			dumpTok(t, g, n)
		}
	}
}

func TestVerifyOk(t *testing.T) {
	for i, tok := range mustLoadTests("verify.json") {
		t.Logf("test %d %s", i, tok.Desc)
		var k Key
		copy(k[:], tok.Secret)
		t.Log("tok")
		dumpTok(t, tok.Token, len(tok.Token))
		ttl := time.Duration(tok.TTLSec) * time.Second
		g := verify(nil, tok.Token, ttl, tok.Now, &k)
		if string(g) != tok.Src {
			t.Errorf("got %#v != exp %#v", string(g), tok.Src)
		}
	}
}

func TestVerifyBad(t *testing.T) {
	for i, tok := range mustLoadTests("invalid.json") {
		t.Logf("test %d %s", i, tok.Desc)
		t.Log(tok.Token)
		var k Key
		copy(k[:], tok.Secret)
		ttl := time.Duration(tok.TTLSec) * time.Second
		if g := verify(nil, tok.Token, ttl, tok.Now, &k); g != nil {
			t.Errorf("got %#v", string(g))
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	k, _ := GenKey()
	msg := []byte("hello")
	g := make([]byte, encodedLen(len(msg)))
	for i := 0; i < b.N; i++ {
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			b.Fatal(err)
		}
		gen(g, msg, iv, time.Now(), k)
		//k.EncryptAndSign([]byte("hello"))
	}
}

func BenchmarkVerifyOk(b *testing.B) {
	tok := mustLoadTests("verify.json")[0]
	var k Key
	copy(k[:], tok.Secret)
	ttl := time.Duration(tok.TTLSec) * time.Second
	for i := 0; i < b.N; i++ {
		verify(nil, tok.Token, ttl, tok.Now, &k)
	}
}

func BenchmarkVerifyBad(b *testing.B) {
	tok := mustLoadTests("invalid.json")[0]
	var k Key
	copy(k[:], tok.Secret)
	ttl := time.Duration(tok.TTLSec) * time.Second
	for i := 0; i < b.N; i++ {
		verify(nil, tok.Token, ttl, tok.Now, &k)
	}
}

func dumpTok(t *testing.T, tok []byte, n int) {
	t.Log(tok[0])
	t.Log(tok[1:][:8])
	t.Log(tok[9:][:16])
	t.Log(tok[25 : n-32])
	t.Log(tok[n-32 : n])
}
