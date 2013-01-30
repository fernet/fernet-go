package fernet_test

import (
	"fmt"
	"github.com/kr/fernet"
	"time"
)

func Example() {
	w := "hello"
	fmt.Println(w)
	k, err := fernet.GenKey()
	if err != nil {
		panic(err)
	}
	token, err := k.EncryptAndSign([]byte(w))
	if err != nil {
		panic(err)
	}
	g := k.VerifyAndDecrypt(token, 60*time.Second)
	fmt.Println(string(g))
	// Output:
	// hello
	// hello
}
