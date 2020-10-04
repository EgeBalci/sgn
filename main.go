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
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/briandowns/spinner"
	sgn "github.com/egebalci/sgn/lib"

	"github.com/fatih/color"
)

// Verbose output mode
var Verbose bool

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

	// Print encoder params...
	printVerbose("Input: " + input)
	printStatus("Input Size: " + strconv.Itoa(len(file)))
	printVerbose("Architecture: x" + strconv.Itoa(encoder.GetArchitecture()))
	printVerbose("Encode Count: " + strconv.Itoa(encoder.EncodingCount))
	printVerbose("Max. Obfuscation Size: " + strconv.Itoa(encoder.ObfuscationLimit))
	printVerbose("Bad Characters: " + *badChars)
	printVerbose("ASCII Mode: " + strconv.FormatBool(*asciPayload))
	printVerbose("Plain Decoder: " + strconv.FormatBool(encoder.PlainDecoder))
	printVerbose("Safe Registers: " + strconv.FormatBool(encoder.SaveRegisters))
	// Calculate evarage garbage instrunction size
	average, err := encoder.CalculateAverageGarbageInstructionSize()
	eror(err)

	printVerbose("Avg. Garbage Size: " + fmt.Sprintf("%f", average))

	if *badChars != "" || *asciPayload {

		// Need to disable verbosity now
		Verbose = false

		s := spinner.New(spinner.CharSets[9], 50*time.Millisecond)
		s.Suffix = " Bruteforcing bad characters..."
		s.Start()

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
		s.Stop()
		printStatus("Success ᕕ( ᐛ )ᕗ")
	} else {
		printVerbose("Encoding payload...")
		p, err := encode(encoder, (file))
		eror(err)
		for i := 0; i < *encCount-1; i++ {
			printVerbose("Encoding payload...")
			p, err = encode(encoder, p)
			eror(err)
		}
		payload = p
	}

	if *output == "" {
		*output = input + ".sgn"
	}
	printStatus("Outfile: " + *output)
	out, err := os.OpenFile(*output, os.O_RDWR|os.O_CREATE, 0755)
	eror(err)
	_, err = out.Write(payload)
	eror(err)
	outputSize := len(payload)
	if Verbose {
		color.Blue("\n" + hex.Dump(payload) + "\n")
	}

	printGood("Final size: " + strconv.Itoa(outputSize))
	printGood("All done ＼(＾O＾)／")
}

// Encode function is the primary encode method for SGN
func encode(encoder *sgn.Encoder, payload []byte) ([]byte, error) {
	red := color.New(color.Bold, color.FgRed).SprintfFunc()
	green := color.New(color.Bold, color.FgGreen).SprintfFunc()

	if encoder.SaveRegisters {
		printVerbose("Adding safe register suffix...")
		payload = append(payload, sgn.SafeRegisterSuffix[encoder.GetArchitecture()]...)
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
	decoderAssembly := encoder.NewDecoderAssembly(ciperedPayload)

	printVerbose("Selected decoder: " + green("\n%s\n", decoderAssembly))
	decoder, ok := encoder.Assemble(decoderAssembly)
	if !ok {
		return nil, errors.New("decoder assembly failed")
	}

	encodedPayload := append(decoder, ciperedPayload...)
	if encoder.PlainDecoder {
		if encoder.SaveRegisters && encoder.EncodingCount == 1 {
			encodedPayload = append(sgn.SafeRegisterPrefix[encoder.GetArchitecture()], encodedPayload...)
		}
		return encodedPayload, nil
	}

	schemaSize := ((len(encodedPayload) - len(ciperedPayload)) / (encoder.GetArchitecture() / 8)) + 1
	randomSchema := encoder.NewCipherSchema(schemaSize)

	printVerbose("Cipher schema: " + red("\n\n%s", sgn.GetSchemaTable(randomSchema)))
	obfuscatedEncodedPayload := encoder.SchemaCipher(encodedPayload, 0, randomSchema)
	final, err := encoder.AddSchemaDecoder(obfuscatedEncodedPayload, randomSchema)
	if err != nil {
		return nil, err
	}

	if encoder.EncodingCount > 1 {
		encoder.EncodingCount--
		return encode(encoder, final)
	}

	if encoder.SaveRegisters {
		printVerbose("Adding safe register prefix...")
		final = append(sgn.SafeRegisterPrefix[encoder.GetArchitecture()], final...)
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

func printStatus(msg string) {
	yellow := color.New(color.Bold, color.FgYellow).PrintfFunc()
	white := color.New(color.FgWhite).PrintfFunc()

	yellow("[*] ")
	white("%s\n", msg)
}

func printGood(msg string) {
	green := color.New(color.Bold, color.FgGreen).PrintfFunc()
	white := color.New(color.FgWhite).PrintfFunc()
	green("[+] ")
	white("%s\n", msg)
}

func printVerbose(msg string) {
	white := color.New(color.FgWhite).PrintfFunc()
	yellow := color.New(color.Bold, color.FgYellow)
	if Verbose {
		yellow.Print("[*] ")
		white("%s\n", msg)
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
