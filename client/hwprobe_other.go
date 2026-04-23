//go:build !amd64 && !386
// +build !amd64,!386

// Hardware probe stubs for non-x86 architectures (arm64, arm, riscv64, …).
//
// ARM / RISC-V CPUs don't have a userspace-readable equivalent of the x86
// extended brand-string leaves — identification goes through kernel-
// exported registers (e.g. /sys/devices/system/cpu/cpu0/regs/identification/
// midr_el1 on arm64) which is handled by the main detection chain.
//
// Similarly, RDTSC is x86-only; ARM has CNTVCT_EL0 but calibration there is
// not worth the extra platform-specific assembly — ARM systems invariably
// expose frequency via the device-tree or /sys/cpufreq.

package main

func cpuBrandStringFromCPUID() string { return "" }
func tscFrequencyMHz() float64        { return 0 }
