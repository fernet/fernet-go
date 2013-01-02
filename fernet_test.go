package fernet

import (
	"crypto/aes"
	"reflect"
	"testing"
	"time"
)

type test struct {
	secret string
	src    []byte
	iv     [aes.BlockSize]byte
	now    time.Time
	ttl    time.Duration
	token  []byte
	desc   string
}

var genTokens = []*test{
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		iv:     [...]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
		now:    time.Date(1985, time.October, 26, 1, 20, 0, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("2woUxqnnpRAj-ztUarjDIfllJBmLiBMjfcmZesHVIhcAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOASy"),
	},
}

var genErrTokens = []*test{
	{
		secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 0, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("FcrjzZRmwcQIuBDcGCh8nGUB8ZD_mXxjqhMln9aIraAAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8kMx7cZZDiiNuT9qRo32pg"),
		desc:   "zero-value key",
	},
}

var verifyTokens = []*test{
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("2woUxqnnpRAj-ztUarjDIfllJBmLiBMjfcmZesHVIhcAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOASy"),
		desc:   "plain style",
	},
}

var verifyBadTokens = []*test{
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("rn9hs9yS0GVWjk4hH822VIwQUWz-_WZWCLzsD7SgV2IAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOASy"),
		desc:   "incorrect mac",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("91GVdgz7jmWR6vJiViEA4u-LhVMhCSr87INSeFwwkYAAAAAAHcCesAABAgMEBQYHCAkKCw=="),
		desc:   "too short",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("%%%%%%%%%%%j-ztUarjDIfllJBmLiBMjfcmZesHVIhcAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOASy"),
		desc:   "invalid base64",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("r-pDJRzyfnW4rYfh-gZek3qA3lnFG8fGaf0qgmZlPL8AAAAAHcCesAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOAQ="),
		desc:   "payload size not multiple of block size",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("ApoqRxzlU8Z9-mPSV6ufXeIgKugRjI_-ugnnqqoCTjQAAAAAHcCesAABAgMEBQYHCAkKCwwNDg91rx5fbHkRnpZBxpOuEAjd"),
		desc:   "payload padding error",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("M0oOEQn9ZTWz212mKeX0qRyi7-wYxJFfsmDMhRazEeAAAAAAVigfvAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOASy"),
		desc:   "far-future TS",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 21, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("2woUxqnnpRAj-ztUarjDIfllJBmLiBMjfcmZesHVIhcAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8tNtXKRlVimf3hMAhjOASy"),
		desc:   "expired ttl",
	},
	{
		secret: "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("fe5sCHPyF13H837yvtc65xAlWfXXP3fEUX_jMiB74EwAAAAAHcCesHV0d3ZxcHNyfXx_fnl4e3otNtXKRlVimf3hMAhjOASy"),
		desc:   "incorrect IV (leads to padding error)",
	},
	{
		secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		src:    []byte("hello"),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("FcrjzZRmwcQIuBDcGCh8nGUB8ZD_mXxjqhMln9aIraAAAAAAHcCesAABAgMEBQYHCAkKCwwNDg8kMx7cZZDiiNuT9qRo32pg"),
		desc:   "zero-value key",
	},
}

func TestGenerate(t *testing.T) {
	for _, tok := range genTokens {
		k := MustDecodeKey(tok.secret)
		g, err := gen(tok.src, tok.iv[:], tok.now, k)
		if !reflect.DeepEqual(g, tok.token) {
			t.Errorf("%#v", string(g))
		}
		if err != nil {
			t.Errorf("err %v", err)
		}
	}
}

func TestGenerateErr(t *testing.T) {
	for _, tok := range genErrTokens {
		k := MustDecodeKey(tok.secret)
		g, err := gen(tok.src, tok.iv[:], tok.now, k)
		if err == nil || err == nil || g != nil {
			t.Errorf("exp nil, got %#v", string(g))
			t.Errorf("err %v", err)
		}
	}
}

func TestVerifyOk(t *testing.T) {
	for i, tok := range verifyTokens {
		t.Logf("test %d %s", i, tok.desc)
		k := MustDecodeKey(tok.secret)
		g := verify(tok.token, tok.ttl, tok.now, k)
		if !reflect.DeepEqual(g, tok.src) {
			t.Errorf("got %#v != exp %#v", string(g), string(tok.src))
		}
	}
}

func TestVerifyBad(t *testing.T) {
	for i, tok := range verifyBadTokens {
		t.Logf("test %d %s", i, tok.desc)
		k := MustDecodeKey(tok.secret)
		if g := verify(tok.token, tok.ttl, tok.now, k); g != nil {
			t.Errorf("got %#v", string(g))
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	k, _ := GenKey()
	for i := 0; i < b.N; i++ {
		k.Generate([]byte("hello"))
	}
}

func BenchmarkVerifyOk(b *testing.B) {
	tok := verifyTokens[0]
	k := MustDecodeKey(tok.secret)
	for i := 0; i < b.N; i++ {
		verify(tok.token, tok.ttl, tok.now, k)
	}
}

func BenchmarkVerifyBad(b *testing.B) {
	tok := verifyBadTokens[0]
	k := MustDecodeKey(tok.secret)
	for i := 0; i < b.N; i++ {
		verify(tok.token, tok.ttl, tok.now, k)
	}
}
