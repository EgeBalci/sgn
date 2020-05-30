package sgn

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
)

// SGN ASM Label Definitions;
//-----------------------------
// {R} 	= RANDOM GENERAL PURPOSE REGISTER
// {K} 	= RANDOM BYTE OF DATA
// {L} 	= RANDOM ASM LABEL
// {G} 	= RANDOM GARBAGE ASSEMBLY
// {F} 	= RANDOM GARBAGE FUNCTION
// {ST} = RANDOM STACK ADDRESS
// {UG}	= RANDOM UNSAFE GARBAGE ASSEMBLY

// GenerateGarbageAssembly generates random garbage instruction(s) assemblies
// based on the subject encoder architecture
func (encoder *Encoder) GenerateGarbageAssembly() string {

	//registerSize := ((rand.Intn(encoder.Architecture/32) + 1) << 2)
	randomGarbageAssembly := GarbageMnemonics[rand.Intn(len(GarbageMnemonics))]

	/* !!! ORDER IS IMPORTANT !!! */

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

	if strings.Contains(randomGarbageAssembly, "{F}") {
		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{F}", encoder.GenerateGarbageFunctionAssembly())
	}

	if strings.Contains(randomGarbageAssembly, "{G}") {
		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{G}", encoder.GenerateGarbageAssembly())
	}

	if strings.Contains(randomGarbageAssembly, "{UG}") {
		randomGarbageAssembly = strings.ReplaceAll(randomGarbageAssembly, "{UG}", encoder.GenerateUnsafeGarbageAssembly())
	}

	return randomGarbageAssembly + ";"
}

// GenerateGarbageInstructions generates random garbage instruction(s)
// with the specified architecture and returns the assembled bytes
func (encoder *Encoder) GenerateGarbageInstructions() ([]byte, error) {

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

	randomGarbageAssembly = encoder.GenerateGarbageAssembly()
	garbage2, ok := encoder.Assemble(randomGarbageAssembly)
	if !ok {
		return nil, errors.New("random garbage instruction assembly failed")
	}
	garbage = append(garbage, garbage2...)

	if len(garbage) <= encoder.ObfuscationLimit {
		return garbage, nil
	}

	return encoder.GenerateGarbageInstructions()
}

// GenerateUnsafeGarbageAssembly generates random unsafe garbage instruction(s) assemblies
// based on the subject encoder architecture
func (encoder *Encoder) GenerateUnsafeGarbageAssembly() string {

	destRegister := encoder.RandomRegister(encoder.architecture / 8)
	unsafeGarbageAssembly := ""

	unsafeGarbageAssembly += fmt.Sprintf("PUSH %s;", destRegister)
	// After saving the target register to stack we can munipulate the register unlimited times
	if CoinFlip() {
		unsafeGarbageAssembly += encoder.GenerateGarbageAssembly()
	}

	// Add first unsafe garbage
	switch rand.Intn(3) {
	case 0:
		unsafeGarbageAssembly += fmt.Sprintf("%s %s,%s;", UnsafeRmMnemonics[rand.Intn(len(UnsafeRmMnemonics))], destRegister, encoder.RandomRegister(encoder.architecture/8))
	case 1:
		unsafeGarbageAssembly += fmt.Sprintf("%s %s,%s;", UnsafeRmMnemonics[rand.Intn(len(UnsafeRmMnemonics))], destRegister, encoder.GetRandomStackAddress())
	case 2:
		unsafeGarbageAssembly += fmt.Sprintf("%s %s,0x%x;", UnsafeImmMnemonics[rand.Intn(len(UnsafeImmMnemonics))], destRegister, RandomByte()%127)
	}

	// Keep adding unsafe garbage by chance
	for {
		if CoinFlip() {
			unsafeGarbageAssembly += encoder.GenerateGarbageAssembly()
		}

		if CoinFlip() {
			switch rand.Intn(3) {
			case 0:
				unsafeGarbageAssembly += fmt.Sprintf("%s %s,%s;", UnsafeRmMnemonics[rand.Intn(len(UnsafeRmMnemonics))], destRegister, encoder.RandomRegister(encoder.architecture/8))
			case 1:
				unsafeGarbageAssembly += fmt.Sprintf("%s %s,%s;", UnsafeRmMnemonics[rand.Intn(len(UnsafeRmMnemonics))], destRegister, encoder.GetRandomStackAddress())
			case 2:
				unsafeGarbageAssembly += fmt.Sprintf("%s %s,0x%x;", UnsafeImmMnemonics[rand.Intn(len(UnsafeImmMnemonics))], destRegister, RandomByte()%127)
			}
		} else {
			break
		}
	}

	if CoinFlip() {
		unsafeGarbageAssembly += encoder.GenerateGarbageAssembly()
	}
	unsafeGarbageAssembly += fmt.Sprintf("POP %s;", destRegister)
	return unsafeGarbageAssembly + ";"
}

// CalculateAverageGarbageInstructionSize calculate the avarage size of generated random garbage instructions
func (encoder *Encoder) CalculateAverageGarbageInstructionSize() (float64, error) {

	var average float64 = 0
	for i := 0; i < 1000; i++ {
		randomGarbageAssembly := encoder.GenerateGarbageAssembly()
		garbage, ok := encoder.Assemble(randomGarbageAssembly)
		if !ok {
			return 0, errors.New("random garbage instruction assembly failed")
		}
		average += float64(len(garbage))
	}
	average = average / 1000
	return average, nil
}

// GenerateGarbageFunctionAssembly generates a function frame assembly with garbage instructions inside
func (encoder *Encoder) GenerateGarbageFunctionAssembly() string {

	bp := ""
	sp := ""

	switch encoder.architecture {
	case 32:
		bp = "EBP"
		sp = "ESP"
	case 64:
		bp = "RBP"
		sp = "RSP"
	default:
		panic(errors.New("invalid architecture selected"))
	}

	prologue := ""
	prologue += fmt.Sprintf("PUSH %s;", bp)
	prologue += fmt.Sprintf("MOV %s,%s;", bp, sp)
	prologue += fmt.Sprintf("SUB %s,0x%d;", sp, int(RandomByte()))

	// Fill the function body with garbage instructions
	garbage := encoder.GenerateGarbageAssembly()

	epilogue := ""
	epilogue += fmt.Sprintf("MOV %s,%s;", sp, bp)
	epilogue += fmt.Sprintf("POP %s;", bp)
	epilogue += "RET;"

	return prologue + garbage + epilogue
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
