//go:build !linux
// +build !linux

// Linux-only helpers are stubbed on macOS / Windows. Callers on those
// platforms don't need sysinfo(2) or /proc parsing because the primary
// detection chain (gopsutil, mach host_statistics, WMI) already works
// natively. These stubs keep the build green and return ok=false so any
// accidental caller falls through to the existing non-Linux code.

package main

func readSysinfo() (memTotal, memUsed, swapTotal, swapUsed uint64, ok bool) {
	return 0, 0, 0, 0, false
}

func readSysinfoUptime() (int64, bool)   { return 0, false }
func readContainerUptime() (int64, bool) { return 0, false }
func readPid1StartTicks() (int64, bool)  { return 0, false }
