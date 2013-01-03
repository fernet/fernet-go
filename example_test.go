package fernet_test

import (
	"encoding/json"
	"fmt"
	"github.com/kr/fernet"
	"os"
	"time"
)

func ExampleKey_EncryptAndSign() {
	k := fernet.Must(fernet.DecodeKey(os.Getenv("MYSECRET")))
	token, err := k.EncryptAndSign([]byte("hello"))
	if err == nil {
		fmt.Println(string(token))
	}
}

func ExampleKey_VerifyAndDecrypt() {
	k := fernet.Must(fernet.DecodeKey(os.Getenv("MYSECRET")))
	token := []byte("…")
	var v struct {
		Username string
	}
	err := json.Unmarshal(k.VerifyAndDecrypt(token, 60*time.Second), &v)
	if err == nil {
		fmt.Println(v.Username)
	}
}
