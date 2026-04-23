//go:build 386
// +build 386

// Hardware probes for 32-bit x86. Same concept as hwprobe_amd64.go but
// limited to CPUID — RDTSC exists on 386 but we don't currently wire it
// into frequency calibration there (TSC detection is an amd64-only code
// path; 386 callers get 0 from tscFrequencyMHz).

package main

import (
	"encoding/binary"
	"strings"
)

// cpuidASM executes the x86 CPUID instruction with EAX=eaxArg and ECX=0,
// returning the four 32-bit output registers. Implemented in hwprobe_386.s.
func cpuidASM(eaxArg uint32) (eax, ebx, ecx, edx uint32)

// cpuBrandStringFromCPUID queries CPUID leaves 0x80000000..0x80000004 to
// build the 48-byte processor brand string. See hwprobe_amd64.go for the
// full rationale — identical logic, just different calling convention
// for 32-bit.
func cpuBrandStringFromCPUID() string {
	maxExt, _, _, _ := cpuidASM(0x80000000)
	if maxExt < 0x80000004 {
		return ""
	}
	var buf [48]byte
	for i, leaf := uint32(0), uint32(0x80000002); leaf <= 0x80000004; i, leaf = i+16, leaf+1 {
		a, b, c, d := cpuidASM(leaf)
		binary.LittleEndian.PutUint32(buf[i:i+4], a)
		binary.LittleEndian.PutUint32(buf[i+4:i+8], b)
		binary.LittleEndian.PutUint32(buf[i+8:i+12], c)
		binary.LittleEndian.PutUint32(buf[i+12:i+16], d)
	}
	raw := string(buf[:])
	if nul := strings.IndexByte(raw, 0); nul >= 0 {
		raw = raw[:nul]
	}
	return strings.Join(strings.Fields(raw), " ")
}

// tscFrequencyMHz is a no-op on 386 — TSC calibration is only wired for
// amd64. 386 callers fall through to /proc/cpuinfo / lscpu / cpufreq.
func tscFrequencyMHz() float64 { return 0 }
