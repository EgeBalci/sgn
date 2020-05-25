package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"

	sgn "github.com/egebalci/sgn/lib"
)

func main() {
	// First open some file
	file, err := ioutil.ReadFile("myfile.bin")
	if err != nil { // check error
		fmt.Println(err)
		return
	}
	// Create a new SGN encoder
	encoder := sgn.NewEncoder()
	// Set the proper architecture
	encoder.SetArchitecture(64)
	// Encode the binary
	encodedBinary, err := encoder.Encode(file)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Print out the hex dump of the encoded binary
	fmt.Println(hex.Dump(encodedBinary))

}
