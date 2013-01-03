package fernet

import (
	"reflect"
	"testing"
	"time"
)

var jsonVerifyTokens = []*test{
	{
		secret: "JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=",
		src:    []byte(`{"email":"harold@heroku.com","id":"123","arbitrary":"data","issued_at":"2013-01-01T16:28:21-08:00"}`),
		now:    time.Date(1985, time.October, 26, 1, 20, 1, 0, time.FixedZone("PDT", -7*3600)),
		ttl:    60 * time.Second,
		token:  []byte("GuAoWrTdBSD3tOAqsTwsqScn7Bx5qi-Yf4R2r1tZ-1MZfU3WxQheTzjwueWMkLCkMbndpcaCULDTmqK4TUgvSa9og_8qSSlyCan3gZrThB1OCJnFxFyf6AgZSic4nGLASedMY8lxTdaOrfe3gdhZGg==|ALJUvh2vqAAOePxO2DN3HA==|2b0eae68d66718f09c62c5fe6803ed25e59a07d7c3080c3e7599337ee17c0d9f"),
		desc:   "json style",
	},
}

func TestJsonVerifyOk(t *testing.T) {
	for i, tok := range jsonVerifyTokens {
		t.Logf("test %d %s", i, tok.desc)
		k := Must(DecodeKey(tok.secret))
		g := jsonVerify(tok.token, tok.ttl, tok.now, k)
		if !reflect.DeepEqual(g, tok.src) {
			t.Errorf("got %#v != exp %#v", string(g), string(tok.src))
		}
	}
}

func BenchmarkJsonVerifyOk(b *testing.B) {
	tok := jsonVerifyTokens[0]
	k := Must(DecodeKey(tok.secret))
	for i := 0; i < b.N; i++ {
		jsonVerify(tok.token, tok.ttl, tok.now, k)
	}
}
