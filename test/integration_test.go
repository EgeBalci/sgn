//go:build windows
// +build windows

package test

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/EgeBalci/sgn/pkg"
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc = kernel32.NewProc("VirtualAlloc")
	virtualFree  = kernel32.NewProc("VirtualFree")

	// NOP NOP NOP RET works on both x86 and x64
	dummyPayload = []byte{0x90, 0x90, 0x90, 0xC3}
)

func TestIntegrationExecution(t *testing.T) {
	var arch int
	if runtime.GOARCH == "386" {
		arch = 32
	} else if runtime.GOARCH == "amd64" {
		arch = 64
	} else {
		t.Skipf("Unsupported architecture: %s", runtime.GOARCH)
	}

	t.Logf("[*] Starting SGN execution stress test (%d-bit)...\n", arch)

	iterations := 1000

	for i := 0; i < iterations; i++ {
		enc, err := sgn.NewEncoder(arch)
		if err != nil {
			t.Fatalf("Failed to init encoder: %v", err)
		}

		enc.ObfuscationLimit = 50

		encoded, err := enc.Encode(dummyPayload)
		if err != nil {
			t.Fatalf("Failed to encode: %v", err)
		}

		addr, _, errInfo := virtualAlloc.Call(
			0,
			uintptr(len(encoded)),
			0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
			0x40,          // PAGE_EXECUTE_READWRITE
		)
		if addr == 0 {
			t.Fatalf("VirtualAlloc failed: %v", errInfo)
		}

		ptr := (*[1 << 30]byte)(unsafe.Pointer(addr))
		copy(ptr[:], encoded)

		// Execute payload
		syscall.Syscall(addr, 0, 0, 0, 0)

		// Free memory
		virtualFree.Call(addr, 0, 0x8000)
	}

	t.Logf("[+] Stress test complete: %d executions with no crashes!", iterations)
}
