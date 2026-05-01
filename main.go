package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EgeBalci/sgn/config"
	sgn "github.com/EgeBalci/sgn/pkg"
	"github.com/EgeBalci/sgn/utils"
	"github.com/briandowns/spinner"

	"github.com/fatih/color"
)

func main() {
	printBanner()
	// Configure the options from the flags/config file
	opts, err := config.ConfigureOptions()
	if err != nil {
		utils.PrintFatal("%s", err)
	}

	// Setup a encoder struct
	payload := []byte{}
	encoder, err := sgn.NewEncoder(opts.Arch)
	if err != nil {
		utils.PrintFatal("%s", err)
	}
	encoder.ObfuscationLimit = opts.ObsLevel
	encoder.PlainDecoder = opts.PlainDecoder
	encoder.EncodingCount = opts.EncCount
	encoder.SaveRegisters = opts.Safe
	file, err := os.ReadFile(opts.Input)
	if err != nil {
		utils.PrintFatal("%s", err)
	}

	spinr := spinner.New(spinner.CharSets[9], 50*time.Millisecond)
	if !opts.Verbose {
		spinr.Start()
	}

	// Print encoder params...
	utils.PrintVerbose("Architecture: x%d", encoder.GetArchitecture())
	utils.PrintVerbose("Encode Count: %d", encoder.EncodingCount)
	utils.PrintVerbose("Max. Obfuscation Size: %d", encoder.ObfuscationLimit)
	utils.PrintVerbose("Bad Characters: %x", opts.BadChars)
	utils.PrintVerbose("ASCII Mode: %t", opts.AsciiPayload)
	utils.PrintVerbose("Plain Decoder: %t", encoder.PlainDecoder)
	utils.PrintVerbose("Safe Registers: %t", encoder.SaveRegisters)
	// Calculate evarage garbage instrunction size
	average, err := encoder.CalculateAverageGarbageInstructionSize()
	if err != nil {
		utils.PrintFatal("%s", err)
	}
	utils.PrintVerbose("Avg. Garbage Size: %f", average)

	if opts.BadChars != "" || opts.AsciiPayload {

		// Need to disable verbosity now
		if utils.Verbose {
			spinr.Start()
			utils.Verbose = false
		}
		spinr.Suffix = " Bruteforcing bad characters..."

		badBytes, err := hex.DecodeString(strings.ReplaceAll(opts.BadChars, `\x`, ""))
		if err != nil {
			utils.PrintFatal("%s", err)
		}

		for {
			encoder.ObfuscationLimit = opts.ObsLevel
			encoder.EncodingCount = opts.EncCount
			encoder.SaveRegisters = opts.Safe
			p, err := encode(encoder, file)
			if err != nil {
				utils.PrintFatal("%s", err)
			}

			asciiOk := !opts.AsciiPayload || utils.IsASCIIPrintable(string(p))
			badBytesOk := len(badBytes) == 0 || !utils.ContainsBytes(p, badBytes)

			if asciiOk && badBytesOk {
				payload = p
				break
			}
			encoder.Seed = (encoder.Seed + 1) % 255
		}
		spinr.Stop()
		utils.PrintStatus("Success ᕕ( ᐛ )ᕗ")
	} else {
		utils.PrintVerbose("Encoding payload...")
		payload, err = encode(encoder, file)
		if err != nil {
			utils.PrintFatal("%s", err)
		}
	}

	spinr.Stop()
	if opts.Output == "" {
		opts.Output = opts.Input + ".sgn"
	}

	utils.PrintStatus("Input: %s", opts.Input)
	utils.PrintStatus("Input Size: %d", len(file))
	utils.PrintStatus("Outfile: %s", opts.Output)
	out, err := os.OpenFile(opts.Output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		utils.PrintFatal("%s", err)
	}
	defer out.Close()
	_, err = out.Write(payload)
	if err != nil {
		utils.PrintFatal("%s", err)
	}
	outputSize := len(payload)
	if utils.Verbose {
		color.Blue("\n" + hex.Dump(payload) + "\n")
	}

	utils.PrintVerbose("Total Garbage Size: %d", encoder.ObfuscationLimit)
	utils.PrintSuccess("Final size: %d", outputSize)
	utils.PrintSuccess("All done ＼(＾O＾)／")
}

// Encode function is the primary encode method for SGN
func encode(encoder *sgn.Encoder, payload []byte) ([]byte, error) {
	red := color.New(color.Bold, color.FgRed).SprintfFunc()
	green := color.New(color.Bold, color.FgGreen).SprintfFunc()
	var final []byte
	if encoder.SaveRegisters {
		utils.PrintVerbose("Adding safe register suffix...")
		payload = append(sgn.SafeRegisterSuffix[encoder.GetArchitecture()], payload...)
	}

	// Add garbage instrctions before the ciphered decoder stub
	garbage, err := encoder.GenerateGarbageInstructions()
	if err != nil {
		return nil, err
	}
	payload = append(garbage, payload...)
	encoder.ObfuscationLimit -= len(garbage)

	utils.PrintVerbose("Ciphering payload...")
	ciperedPayload := sgn.CipherADFL(payload, encoder.Seed)
	decoderAssembly, err := encoder.NewDecoderAssembly(len(ciperedPayload))
	if err != nil {
		utils.PrintFatal("%s", err)
	}
	utils.PrintVerbose("Selected decoder: %s", green("\n%s\n", decoderAssembly))
	decoder, ok := encoder.Assemble(decoderAssembly)
	if !ok {
		return nil, errors.New("decoder assembly failed")
	}

	encodedPayload := append(decoder, ciperedPayload...)
	if encoder.PlainDecoder {
		final = encodedPayload
	} else {
		schemaSize := ((len(encodedPayload) - len(ciperedPayload)) / 4) + 1
		for len(encodedPayload) < schemaSize*4 {
			encodedPayload = append(encodedPayload, 0x90)
		}
		randomSchema := encoder.NewCipherSchema(schemaSize)
		utils.PrintVerbose("Cipher schema: %s", red("\n\n%s", sgn.GetSchemaTable(randomSchema)))
		obfuscatedEncodedPayload := encoder.SchemaCipher(encodedPayload, 0, randomSchema)
		final, err = encoder.AddSchemaDecoder(obfuscatedEncodedPayload, randomSchema)
		if err != nil {
			return nil, err
		}

	}

	if encoder.SaveRegisters {
		utils.PrintVerbose("Adding safe register prefix...")
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

func printBanner() {
	banner, _ := base64.StdEncoding.DecodeString("ICAgICAgIF9fICAgXyBfXyAgICAgICAgX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXyAKICBfX18gLyAvICAoXykgL19fX19fIF8vIC9fX19fIF8gIF9fXyBfX19fIF8gIF9fXyAgX19fIF8oXykKIChfLTwvIF8gXC8gLyAgJ18vIF8gYC8gX18vIF8gYC8gLyBfIGAvIF8gYC8gLyBfIFwvIF8gYC8gLyAKL19fXy9fLy9fL18vXy9cX1xcXyxfL1xfXy9cXyxfLyAgXF8sIC9cXyxfLyAvXy8vXy9cXyxfL18vICAKPT09PT09PT1bQXV0aG9yOi1FZ2UtQmFsY8SxLV09PT09L19fXy89PT09PT09JXM9PT09PT09PT0gIAogICAg4pS74pSB4pS7IO+4teODvShg0JTCtCnvvonvuLUg4pS74pSB4pS7ICAgICAgICAgICAo44OOIOOCnNCU44KcKeODjiDvuLUg5LuV5pa544GM44Gq44GECg==")

	fmt.Printf(string(banner)+"\n", strings.Split(config.Version, "-")[0])
}
