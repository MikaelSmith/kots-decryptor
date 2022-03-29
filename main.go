package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/MikaelSmith/kots-decryptor/crypto"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: kots-decryptor <cipher> <encrypted value>")
		os.Exit(1)
	}
	cipher, err := crypto.AESCipherFromString(os.Args[1])
	if err != nil {
		fmt.Println("Error decoding cipher:", err)
		os.Exit(2)
	}

	decoded, err := base64.StdEncoding.DecodeString(os.Args[2])
	if err != nil {
		fmt.Println("Encrypted value must be base64 encoded:", err)
		os.Exit(2)
	}

	val, err := cipher.Decrypt(decoded)
	if err != nil {
		fmt.Println("Error decrypting value:", err)
		os.Exit(2)
	}

	fmt.Println(string(val))
	return
}
