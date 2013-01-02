package fernet_test

import (
	"encoding/json"
	"fmt"
	"github.com/kr/fernet"
	"os"
	"time"
)

func ExampleGenKey() {
	k, _ := fernet.GenKey()
	fmt.Println("the secret is", k.Encode())
}

func ExampleGenerate() {
	k := fernet.MustDecodeKey(os.Getenv("MYSECRET"))
	token, err := k.Generate([]byte("hello"))
	if err == nil {
		fmt.Println(string(token))
	}
}

func ExampleVerify() {
	k := fernet.MustDecodeKey(os.Getenv("MYSECRET"))
	token := []byte("…")
	var v struct {
		Username string
	}
	err := json.Unmarshal(k.Verify(token, 60*time.Second), &v)
	if err == nil {
		fmt.Println(v.Username)
	}
}
