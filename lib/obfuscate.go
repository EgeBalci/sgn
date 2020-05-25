package sgn

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
)

// GenerateGarbageAssembly generates random garbage instruction(s) assemblies
// with the subject encoder architecture
func (encoder Encoder) GenerateGarbageAssembly() string {

	//registerSize := ((rand.Intn(encoder.Architecture/32) + 1) << 2)
	randomGarbageAssembly := GarbageMnemonics[rand.Intn(len(GarbageMnemonics))]

	if strings.Contains(randomGarbageAssembly, "{R}") {
		register := encoder.RandomRegister(encoder.architecture / 8)

		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{R}", register)
	}

	if strings.Contains(randomGarbageAssembly, "{K}") {
		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{K}", fmt.Sprintf("0x%x", RandomByte()))
	}

	if strings.Contains(randomGarbageAssembly, "{L}") {
		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{L}", RandomLabel())
	}

	if strings.Contains(randomGarbageAssembly, "{G}") {
		innerRandomGarbageAssembly := encoder.GenerateGarbageAssembly()
		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{G}", innerRandomGarbageAssembly)
	}
	return "\t" + randomGarbageAssembly + ";\n"
}

// GenerateGarbageInstructions generates random garbage instruction(s)
// with the specified architecture and returns the assembled bytes
func (encoder Encoder) GenerateGarbageInstructions() ([]byte, error) {

	randomGarbageAssembly := encoder.GenerateGarbageAssembly()

	garbage, ok := encoder.Assemble(randomGarbageAssembly)
	if !ok {
		return nil, errors.New("random garbage instruction assembly failed")
	}

	if CoinFlip() {
		garbageJmp, err := encoder.GenerateGarbageJump()
		if err != nil {
			return nil, err
		}
		if CoinFlip() {
			garbage = append(garbageJmp, garbage...)
		} else {
			garbage = append(garbage, garbageJmp...)
		}
	}

	if len(garbage) <= encoder.ObfuscationLimit {
		encoder.ObfuscationLimit -= len(garbage)
		return garbage, nil
	}

	return encoder.GenerateGarbageInstructions()
}

// GenerateGarbageFunction generates a meaningless function with garbage instructions inside
func (encoder Encoder) GenerateGarbageFunction() ([]byte, error) {

	prologue := ""
	prologue += "PUSH EBP;"
	prologue += "MOV EBP,ESP;"
	prologue += fmt.Sprintf("SUB ESP,0x%d", int(RandomByte()))

	prologueBin, ok := encoder.Assemble(prologue)
	if !ok {
		return nil, errors.New("garbage function assembly failed")
	}

	//
	garbage, err := encoder.GenerateGarbageInstructions()
	if err != nil {
		return nil, err
	}

	epilogue := ""
	epilogue += "MOV ESP,EBP;"
	epilogue += "POP EBP;"
	epilogue += "RET;"

	epilogueBin, ok := encoder.Assemble(prologue)
	if !ok {
		return nil, errors.New("random garbage instruction assembly failed")
	}

	return append(append(prologueBin, garbage...), epilogueBin...), nil
}

// GenerateGarbageJump generates a JMP instruction over random bytes
func (encoder Encoder) GenerateGarbageJump() ([]byte, error) {
	randomBytes := RandomBytes(encoder.ObfuscationLimit / 10)
	garbageJmp, err := encoder.AddJmpOver(randomBytes)
	if err != nil {
		return nil, err
	}
	return garbageJmp, nil
}

// RandomLabel generates a random assembly label
func RandomLabel() string {
	numbers := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 5)
	for i := range b {
		b[i] = numbers[rand.Intn(len(numbers))]
	}
	return string(b)
}
