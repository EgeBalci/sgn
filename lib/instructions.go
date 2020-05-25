package sgn

// ConditionalJumpMnemonics contains the conditional branching instruction mnemonics
var ConditionalJumpMnemonics = []string{
	"JAE",
	"JA",
	"JBE",
	"JB",
	"JC",
	"JE",
	"JGE",
	"JG",
	"JLE",
	"JL",
	"JNAE",
	"JNA",
	"JNBE",
	"JNB",
	"JNC",
	"JNE",
	"JNGE",
	"JNG",
	"JNLE",
	"JNL",
	"JNO",
	"JNP",
	"JNS",
	"JNZ",
	"JO",
	"JPE",
	"JPO",
	"JP",
	"JS",
	"JZ",
}

// GarbageMnemonics array containing instructions
// that does not affect the overall execution of the program
// !!! These instructions must not clobber registers or stack flags may be affected !!!
var GarbageMnemonics = []string{
	";", // no instruction (empty)
	"NOP",
	"CLD",
	"CLC",
	"CMC",
	"WAIT",
	"FNOP",
	"FXAM",
	"FTST",
	"JMP 2",
	"BT {R},{R}",
	"CMP {R},{R}",
	"MOV {R},{R}",
	"XCHG {R},{R}",
	"TEST {R},{R}",
	"CMOVA {R},{R}",
	"CMOVB {R},{R}",
	"CMOVC {R},{R}",
	"CMOVE {R},{R}",
	"CMOVG {R},{R}",
	"CMOVL {R},{R}",
	"CMOVO {R},{R}",
	"CMOVP {R},{R}",
	"CMOVS {R},{R}",
	"CMOVZ {R},{R}",
	"CMOVAE {R},{R}",
	"CMOVGE {R},{R}",
	"CMOVLE {R},{R}",
	"CMOVNA {R},{R}",
	"CMOVNB {R},{R}",
	"CMOVNC {R},{R}",
	"CMOVNE {R},{R}",
	"CMOVNG {R},{R}",
	"CMOVNL {R},{R}",
	"CMOVNO {R},{R}",
	"CMOVNP {R},{R}",
	"CMOVNS {R},{R}",
	"CMOVNZ {R},{R}",
	"CMOVPE {R},{R}",
	"CMOVPO {R},{R}",
	"CMOVBE {R},{R}",
	"CMOVNAE {R},{R}",
	"CMOVNBE {R},{R}",
	"CMOVNLE {R},{R}",
	"CMOVNGE {R},{R}",
	"JMP {L};{G};{L}:",
	"NOT {R};{G};NOT {R}",
	"INC {R};{G};DEC {R}",
	"DEC {R};{G};INC {R}",
	"PUSH {R};{G};POP {R}",
	"BSWAP {R};{G};BSWAP {R}",
	"ADD {R},{K};{G};SUB {R},{K}",
	"SUB {R},{K};{G};ADD {R},{K}",
	"ROR {R},{K};{G};ROL {R},{K}",
	"ROL {R},{K};{G};ROR {R},{K}",
	"PUSH EBP;MOV EBP,ESP;{G};MOV ESP,EBP;POP EBP"} // function prologue/apilogue

// JMP 2 -> Jumps to next instruction

func addGarbageJumpMnemonics() {
	for _, i := range ConditionalJumpMnemonics {
		GarbageMnemonics = append(GarbageMnemonics, i+" 2")
	}

	for _, i := range ConditionalJumpMnemonics {
		GarbageMnemonics = append(GarbageMnemonics, i+" {L};{G};{L}:")
	}
}
