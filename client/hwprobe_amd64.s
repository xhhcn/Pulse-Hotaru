// +build amd64

#include "textflag.h"

// Hardware probe primitives for x86_64. Both CPUID and RDTSC are
// unprivileged instructions — they work from any user-space process,
// including inside restricted LXC containers where /proc and /sys are
// masked by lxcfs.

// func cpuidASM(eaxArg uint32) (eax, ebx, ecx, edx uint32)
//
// Executes CPUID with EAX=eaxArg and ECX=0, returning the four 32-bit
// output registers.
TEXT ·cpuidASM(SB), NOSPLIT, $0-24
	MOVL eaxArg+0(FP), AX
	XORL CX, CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

// func rdtsc() uint64
//
// Reads the Time-Stamp Counter. The TSC is a 64-bit register that
// increments at a fixed rate (invariant-TSC CPUs — all x86_64 CPUs since
// Nehalem / Bulldozer). RDTSC places the low 32 bits in EAX and the high
// 32 bits in EDX; we combine them into the return slot.
TEXT ·rdtsc(SB), NOSPLIT, $0-8
	RDTSC
	SHLQ $32, DX
	ORQ  DX, AX
	MOVQ AX, ret+0(FP)
	RET
