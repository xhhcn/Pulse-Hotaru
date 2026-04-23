// +build 386

#include "textflag.h"

// func cpuidASM(eaxArg uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuidASM(SB), NOSPLIT, $0-20
	MOVL eaxArg+0(FP), AX
	XORL CX, CX
	CPUID
	MOVL AX, eax+4(FP)
	MOVL BX, ebx+8(FP)
	MOVL CX, ecx+12(FP)
	MOVL DX, edx+16(FP)
	RET
