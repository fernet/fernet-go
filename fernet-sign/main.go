package main

import (
	"fmt"
	"github.com/fernet/fernet-go"
	"io/ioutil"
	"log"
	"os"
)

const Usage = `Usage: fernet-sign ENV

Fernet-sign encrypts and signs its input and prints the resulting token.
It uses the key in environment variable ENV.`

func main() {
	log.SetFlags(0)
	log.SetPrefix("fernet: ")
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, Usage)
		os.Exit(2)
	}
	key, err := fernet.DecodeKey(os.Getenv(os.Args[1]))
	if err != nil {
		log.Fatalln(err)
	}

	b, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln(err)
	}

	t, err := fernet.EncryptAndSign(b, key)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = os.Stdout.Write(append(t, '\n'))
	if err != nil {
		log.Fatalln(err)
	}
}
