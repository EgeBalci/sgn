package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode"

	sgn "github.com/EgeBalci/sgn/pkg"
	"github.com/briandowns/spinner"

	"github.com/fatih/color"
)

// Verbose output mode
var Verbose bool
var spinr = spinner.New(spinner.CharSets[9], 50*time.Millisecond)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {

	printBanner()
	help := flag.Bool("h", false, "Print help")
	output := flag.String("o", "", "Encoded output binary name")
	arch := flag.Int("a", 32, "Binary architecture (32/64)")
	encCount := flag.Int("c", 1, "Number of times to encode the binary (increases overall size)")
	obsLevel := flag.Int("max", 20, "Maximum number of bytes for obfuscation")
	encDecoder := flag.Bool("plain-decoder", false, "Do not encode the decoder stub")
	asciPayload := flag.Bool("asci", false, "Generates a full ASCI printable payload (takes very long time to bruteforce)")
	saveRegisters := flag.Bool("safe", false, "Do not modify any register values")
	badChars := flag.String("badchars", "", "Don't use specified bad characters given in hex format (\\x00\\x01\\x02...)")
	flag.BoolVar(&Verbose, "v", false, "More verbose output")
	flag.Parse()

	if len(os.Args) < 2 || *help {
		printHelp()
		os.Exit(1)
	}

	// Setup a encoder struct
	input := os.Args[len(os.Args)-1]
	payload := []byte{}
	encoder := sgn.NewEncoder()
	encoder.ObfuscationLimit = *obsLevel
	encoder.PlainDecoder = *encDecoder
	encoder.EncodingCount = *encCount
	encoder.SaveRegisters = *saveRegisters
	eror(encoder.SetArchitecture(*arch))
	file, err := ioutil.ReadFile(input)
	eror(err)

	if !Verbose {
		spinr.Start()
	}

	// Print encoder params...
	printVerbose("Architecture: x%d", encoder.GetArchitecture())
	printVerbose("Encode Count: %d", encoder.EncodingCount)
	printVerbose("Max. Obfuscation Size: %d", encoder.ObfuscationLimit)
	printVerbose("Bad Characters: %x", *badChars)
	printVerbose("ASCII Mode: %t", *asciPayload)
	printVerbose("Plain Decoder: %t", encoder.PlainDecoder)
	printVerbose("Safe Registers: %t", encoder.SaveRegisters)
	// Calculate evarage garbage instrunction size
	average, err := encoder.CalculateAverageGarbageInstructionSize()
	eror(err)
	printVerbose("Avg. Garbage Size: %f", average)

	if *badChars != "" || *asciPayload {

		// Need to disable verbosity now
		if Verbose {
			spinr.Start()
			Verbose = false
		}
		spinr.Suffix = " Bruteforcing bad characters..."

		badBytes, err := hex.DecodeString(strings.ReplaceAll(*badChars, `\x`, ""))
		eror(err)

		for {
			p, err := encode(encoder, file)
			eror(err)

			if (*asciPayload && isASCIIPrintable(string(p))) || (len(badBytes) > 0 && !containsBytes(p, badBytes)) {
				payload = p
				break
			}
			encoder.Seed = (encoder.Seed + 1) % 255
		}
		spinr.Stop()
		printStatus("Success ᕕ( ᐛ )ᕗ")
	} else {
		printVerbose("Encoding payload...")
		payload, err = encode(encoder, file)
		eror(err)
	}

	spinr.Stop()
	if *output == "" {
		*output = input + ".sgn"
	}

	printStatus("Input: %s", input)
	printStatus("Input Size: %d", len(file))
	printStatus("Outfile: %s", *output)
	out, err := os.OpenFile(*output, os.O_RDWR|os.O_CREATE, 0755)
	eror(err)
	_, err = out.Write(payload)
	eror(err)
	outputSize := len(payload)
	if Verbose {
		color.Blue("\n" + hex.Dump(payload) + "\n")
	}

	printGood("Final size: %d", outputSize)
	printGood("All done ＼(＾O＾)／")
}

// Encode function is the primary encode method for SGN
func encode(encoder *sgn.Encoder, payload []byte) ([]byte, error) {
	red := color.New(color.Bold, color.FgRed).SprintfFunc()
	green := color.New(color.Bold, color.FgGreen).SprintfFunc()
	var final []byte

	if encoder.SaveRegisters {
		printVerbose("Adding safe register suffix...")
		payload = append(sgn.SafeRegisterSuffix[encoder.GetArchitecture()], payload...)
	}

	// Add garbage instrctions before the ciphered decoder stub
	garbage, err := encoder.GenerateGarbageInstructions()
	if err != nil {
		return nil, err
	}
	payload = append(garbage, payload...)
	encoder.ObfuscationLimit -= len(garbage)

	printVerbose("Ciphering payload...")
	ciperedPayload := sgn.CipherADFL(payload, encoder.Seed)
	decoderAssembly := encoder.NewDecoderAssembly(len(ciperedPayload))
	printVerbose("Selected decoder: %s", green("\n%s\n", decoderAssembly))
	decoder, ok := encoder.Assemble(decoderAssembly)
	if !ok {
		return nil, errors.New("decoder assembly failed")
	}

	encodedPayload := append(decoder, ciperedPayload...)
	if encoder.PlainDecoder {
		final = encodedPayload
	} else {
		schemaSize := ((len(encodedPayload) - len(ciperedPayload)) / (encoder.GetArchitecture() / 8)) + 1
		randomSchema := encoder.NewCipherSchema(schemaSize)
		printVerbose("Cipher schema: %s", red("\n\n%s", sgn.GetSchemaTable(randomSchema)))
		obfuscatedEncodedPayload := encoder.SchemaCipher(encodedPayload, 0, randomSchema)
		final, err = encoder.AddSchemaDecoder(obfuscatedEncodedPayload, randomSchema)
		if err != nil {
			return nil, err
		}

	}

	if encoder.SaveRegisters {
		printVerbose("Adding safe register prefix...")
		final = append(sgn.SafeRegisterPrefix[encoder.GetArchitecture()], final...)
	}

	if encoder.EncodingCount > 1 {
		encoder.EncodingCount--
		encoder.Seed = sgn.GetRandomByte()
		final, err = encode(encoder, final)
		if err != nil {
			return nil, err
		}
	}

	return final, nil
}

// checks if a byte array contains any element of another byte array
func containsBytes(data, any []byte) bool {
	for _, b := range any {
		if bytes.Contains(data, []byte{b}) {
			return true
		}
	}
	return false
}

// checks if s is ascii and printable, aka doesn't include tab, backspace, etc.
func isASCIIPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func eror(err error) {
	if err != nil {
		pc, _, _, ok := runtime.Caller(1)
		details := runtime.FuncForPC(pc)
		if ok && details != nil {
			log.Fatalf("[%s] ERROR: %s\n", strings.ToUpper(strings.Split(details.Name(), ".")[1]), err)
		} else {
			log.Fatalf("[UNKNOWN] ERROR: %s\n", err)
		}
	}
}

func printStatus(format string, a ...interface{}) {
	yellow := color.New(color.Bold, color.FgYellow).PrintfFunc()
	yellow("[*] ")
	fmt.Printf(format+"\n", a...)
}

func printGood(format string, a ...interface{}) {
	green := color.New(color.Bold, color.FgGreen).PrintfFunc()
	green("[+] ")
	fmt.Printf(format+"\n", a...)
}

func printVerbose(format string, a ...interface{}) {
	if Verbose {
		yellow := color.New(color.Bold, color.FgYellow)
		yellow.Print("[*] ")
		fmt.Printf(format+"\n", a...)
	}
	if !strings.Contains(format, ":") {
		spinr.Suffix = fmt.Sprintf(" "+format, a...)
	}
}

func printHelp() {
	fmt.Printf("Usage: %s [OPTIONS] <FILE>\n", os.Args[0])
	flag.PrintDefaults()
}

func printBanner() {
	banner, _ := base64.StdEncoding.DecodeString("ICAgICAgIF9fICAgXyBfXyAgICAgICAgX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXyAKICBfX18gLyAvICAoXykgL19fX19fIF8vIC9fX19fIF8gIF9fXyBfX19fIF8gIF9fXyAgX19fIF8oXykKIChfLTwvIF8gXC8gLyAgJ18vIF8gYC8gX18vIF8gYC8gLyBfIGAvIF8gYC8gLyBfIFwvIF8gYC8gLyAKL19fXy9fLy9fL18vXy9cX1xcXyxfL1xfXy9cXyxfLyAgXF8sIC9cXyxfLyAvXy8vXy9cXyxfL18vICAKPT09PT09PT1bQXV0aG9yOi1FZ2UtQmFsY8SxLV09PT09L19fXy89PT09PT09djIuMC4wPT09PT09PT09ICAKICAgIOKUu+KUgeKUuyDvuLXjg70oYNCUwrQp776J77i1IOKUu+KUgeKUuyAgICAgICAgICAgKOODjiDjgpzQlOOCnCnjg44g77i1IOS7leaWueOBjOOBquOBhAo=")
	fmt.Println(string(banner))
}
