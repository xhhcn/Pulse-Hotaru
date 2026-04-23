//go:build amd64
// +build amd64

// Hardware probes for x86_64. These functions execute unprivileged CPU
// instructions directly (CPUID, RDTSC) and are therefore independent of
// /proc, /sys, lxcfs, and every other kernel / userspace interface that
// a restricted container runtime can mask or lie about. They're the
// authoritative CPU identification and frequency source on LXC / Docker
// / k8s containers where /proc/cpuinfo is unreadable or faked.

package main

import (
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// ─── CPUID ──────────────────────────────────────────────────────────────

// cpuidASM executes the x86 CPUID instruction with EAX=eaxArg and ECX=0,
// returning the four 32-bit output registers. Implemented in hwprobe_amd64.s.
func cpuidASM(eaxArg uint32) (eax, ebx, ecx, edx uint32)

// cpuBrandStringFromCPUID queries CPUID leaves 0x80000000..0x80000004 to
// build the 48-byte "processor brand string" that Intel/AMD bake into
// every x86_64 chip (e.g. "AMD EPYC 7402P 24-Core Processor",
// "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz").
//
// Returns "" if the CPU doesn't expose the extended brand leaves. Every
// x86_64 CPU manufactured in the last two decades does, so on amd64 this
// is effectively guaranteed to succeed.
//
// This path is the authoritative CPU model source inside LXC containers
// where /proc/cpuinfo has been masked by a broken lxcfs — it asks the
// silicon directly, which no FUSE daemon can intercept.
func cpuBrandStringFromCPUID() string {
	// Leaf 0x80000000 returns (EAX = max supported extended leaf).
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
	// Brand string is NUL-padded; trim and collapse inner whitespace.
	raw := string(buf[:])
	if nul := strings.IndexByte(raw, 0); nul >= 0 {
		raw = raw[:nul]
	}
	return strings.Join(strings.Fields(raw), " ")
}

// ─── RDTSC-based frequency calibration ─────────────────────────────────

// rdtsc returns the current x86 Time-Stamp Counter value.
// Implemented in hwprobe_amd64.s.
func rdtsc() uint64

var (
	tscFreqMHzOnce  sync.Once
	tscFreqMHzValue float64
)

// measureTSCFrequencyMHz calibrates the TSC against wall-clock time and
// returns the effective CPU frequency in MHz. On every x86_64 CPU from
// the last ~15 years the TSC increments at the nominal CPU base frequency
// (invariant TSC), so this gives an accurate speed reading that is
// *independent* of /proc/cpuinfo, lscpu, /sys/devices/system/cpu/cpufreq
// and every other kernel/userspace interface that lxcfs can break.
//
// Two back-to-back samples: the first primes CPU caches and frequency
// scaling; the second is the authoritative measurement.
func measureTSCFrequencyMHz() float64 {
	sample := func(d time.Duration) float64 {
		start := time.Now()
		t1 := rdtsc()
		time.Sleep(d)
		t2 := rdtsc()
		elapsed := time.Since(start).Seconds()
		if elapsed <= 0 || t2 <= t1 {
			return 0
		}
		return float64(t2-t1) / 1e6 / elapsed
	}
	_ = sample(10 * time.Millisecond)
	return sample(70 * time.Millisecond)
}

// tscFrequencyMHz returns the TSC-calibrated CPU frequency in MHz,
// computing it on first call and caching the result for the process
// lifetime (one measurement costs ~80 ms). Safe for concurrent use.
func tscFrequencyMHz() float64 {
	tscFreqMHzOnce.Do(func() {
		tscFreqMHzValue = measureTSCFrequencyMHz()
	})
	return tscFreqMHzValue
}
