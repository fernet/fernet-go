package main

import (
	"fmt"
	"github.com/fernet/fernet-go"
	"log"
)

func main() {
	var key fernet.Key
	if err := key.Generate(); err != nil {
		log.Fatal(err)
	}
	fmt.Println(key.Encode())
}
