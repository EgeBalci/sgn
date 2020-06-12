[![BANNER](https://github.com/EgeBalci/sgn/raw/master/img/banner.png)](https://github.com/EgeBalci/sgn)

[![Go Report Card](https://goreportcard.com/badge/github.com/egebalci/sgn)](https://goreportcard.com/report/github.com/egebalci/sgn)
[![Open Issues](https://img.shields.io/github/issues/egebalci/sgn?style=flat-square&color=red)](https://github.com/EgeBalci/sgn/issues)
[![License](https://img.shields.io/github/license/egebalci/amber.svg?style=flat-square)](https://raw.githubusercontent.com/EgeBalci/sgn/master/LICENSE)
[![Twitter](https://img.shields.io/badge/twitter-@egeblc-55acee.svg?style=flat-square)](https://twitter.com/egeblc)

SGN is a polymorphic binary encoder for offensive security purposes such as generating statically undetecable binary payloads. It uses a additive feedback loop to encode given binary instructions similar to [LSFR](https://en.wikipedia.org/wiki/Linear-feedback_shift_register). This project is the reimplementation of the [original Shikata ga nai](https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/shikata_ga_nai.rb) in golang with many improvements. 


## How? & Why?
For offensive security community, the original implementation of shikata ga nai encoder is considered to be the best shellcode encoder(until now). But over the years security researchers found several pitfalls for statically detecing the encoder(related work [FireEye article](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html)). The main motive for this project was to create a better encoder that encodes the given binary to the point it is identical with totally random data and not possible to detect the presence of a decoder. With the help of [keystone](http://www.keystone-engine.org/) assembler library following improvments are implemented.

- [x] 64 bit support. `Finally properly encoded x64 shellcodes !`
- [x] New smaller decoder stub. `LFSR key reduced to 1 byte`
- [x] Encoded stub with pseudo random schema. `Decoder stub is also encoded with a psudo random schema`
- [x] No visible loop condition `Stub decodes itself WITHOUT using any loop conditions !!` 
- [x] Decoder stub obfuscation. `Random garbage instruction generator added with keystone`
- [x] Safe register option. `Non of the registers are clobbered (optional preable, may reduce polimorphism)` 

## Install

**Dependencies:**

Only dependencies required is keystone and capstone libraries. For easily installing capstone and keystone libararies check the table below;


<table>
  <tr>
      <th>OS</th>
      <th>Install Command</th>
  </tr>
  <tr>
      <td>Ubuntu/Debian</td>
      <td>sudo apt-get install libcapstone-dev</td>
  </tr>
  <tr>
      <td>Arch Linux</td>
      <td>sudo pacman -S capstone keystone</td>
  </tr>
  <tr>
      <td>Mac</td>
      <td>brew install keystone capstone</td>
  </tr>
  <tr>
      <td>Fedora</td>
      <td>sudo yum install keystone capstone</td>
  </tr>
  <tr>
      <td>Windows/All Other...</td>
      <td><a href="https://www.capstone-engine.org/documentation.html">CHECK HERE</a></td>
  </tr>
</table>

Installation of keystone library can be little tricky in some cases. [Check here](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE.md) if you have any problem with yor packet manager.

Then just go get it ツ

```
go get github.com/egebalci/sgn
```

**Usage**

`-h` is pretty self explanatory use `-v` if you want to see what's going on behind the scenes `( ͡° ͜ʖ ͡°)_/¯`
<p align="center">
  <img src="https://github.com/EgeBalci/sgn/raw/master/img/usage.gif">
</p>


```
       __   _ __        __                               _ 
  ___ / /  (_) /_____ _/ /____ _  ___ ____ _  ___  ___ _(_)
 (_-</ _ \/ /  '_/ _ `/ __/ _ `/ / _ `/ _ `/ / _ \/ _ `/ / 
/___/_//_/_/_/\_\\_,_/\__/\_,_/  \_, /\_,_/ /_//_/\_,_/_/  
========[Author:-Ege-Balcı-]====/___/=======v2.0.0=========  
    ┻━┻ ︵ヽ(`Д´)ﾉ︵ ┻━┻           (ノ ゜Д゜)ノ ︵ 仕方がない

Usage: sgn [OPTIONS] <FILE>
  -a int
    	Binary architecture (32/64) (default 32)
  -asci
    	Generates a full ASCI printable payload (takes very long time to bruteforce)
  -badchars string
    	Don't use specified bad characters given in hex format (\x00\x01\x02...)
  -c int
    	Number of times to encode the binary (increases overall size) (default 1)
  -h	Print help
  -max int
    	Maximum number of bytes for obfuscation (default 20)
  -o string
    	Encoded output binary name
  -plain-decoder
    	Do not encode the decoder stub
  -safe
    	Do not modify and register values
  -v	More verbose output
```


## Using As Library
Warning !! SGN package is still under development for better performance and several improvements. Most of the functions are subject to change.

```
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
```


## Execution Flow

The following image is a basic workflow diagram for the encoder. But keep in mind that the sizes, locations and orders will change for garbage instructions, decoders and schema decoders on each iteration. 

<p align="center">
  <img src="https://github.com/EgeBalci/sgn/raw/master/img/flow.png">
</p>

LFSR itself is pretty powerful in terms of probability space. For even more polimorphism garbage instructions are appended at the begining of the unencoded raw payload. Below image shows the the companion matrix of the characteristic polynomial of the LFSR and denoting the seed as a column vector, the state of the register in Fibonacci configuration after k steps.

<p align="center">
  <img src="https://github.com/EgeBalci/sgn/raw/master/img/matrices.svg">
</p>


## [Challenge](https://github.com/EgeBalci/sgn/wiki/Challange_Guidelines)

Considering the probability space of this encoder I personally don't think that any rule based static detection mechanism can detect the binaries that are encoded with SGN. In fact I am willing to give out the donation money for this project as a symbolic prize if anyone can write a YARA rule that can detect every encoded output. Check out [***HERE***](https://github.com/EgeBalci/sgn/wiki/Challange_Guidelines) for the guidelines and rules for claiming the donation money.

[***Current Donation Amount***](https://www.blockchain.com/tr/btc/address/1615NKMjpHShh3hWHrazWybgJxpqZgz4f2)

[![QR](https://github.com/EgeBalci/sgn/raw/master/img/btc_qr.png)](https://www.blockchain.com/tr/btc/address/1615NKMjpHShh3hWHrazWybgJxpqZgz4f2)

If you tried and failed please consider donating `[̲̅$̲̅(̲̅ ͡° ͜ʖ ͡°̲̅)̲̅$̲̅]`