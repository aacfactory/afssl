package main

import (
	"fmt"
	"github.com/aacfactory/afssl/commands/afssl/base"
	"os"
)

// main
// afssl --type={RSA,ECDSA,ED25519,SM2} --ca --expire={days} --cn={CN} {dst path}
func main() {
	err := base.Generate(os.Args[1:])
	if err != nil {
		fmt.Println(fmt.Sprintf("%+v", err))
		return
	}
	fmt.Println("afssl: generate succeed!")
}
