package main

import (
	"encoding/hex"
	"fmt"
	"os"

	sgn "github.com/egebalci/sgn/pkg"
)

func main() {
	// First open some file
	file, err := os.ReadFile("myfile.bin")
	if err != nil { // check error
		fmt.Println(err)
		return
	}
	// Create a new SGN encoder
	encoder, err := sgn.NewEncoder(64)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Encode the binary
	encodedBinary, err := encoder.Encode(file)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Print out the hex dump of the encoded binary
	fmt.Println(hex.Dump(encodedBinary))

}
