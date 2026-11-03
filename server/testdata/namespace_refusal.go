//go:build linux

// This fixture denies namespace creation only in its own process descendants.
package main

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) > 2 && os.Args[1] == "child" {
		if err := os.WriteFile(os.Args[2], []byte("child-started"), 0600); err != nil {
			os.Exit(2)
		}
		return
	}
	runtime.LockOSThread()
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_UNSHARE},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Exit(3)
	}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&program))); errno != 0 {
		os.Exit(4)
	}
	if err := unix.Exec(os.Args[1], os.Args[1:], os.Environ()); err != nil {
		os.Exit(5)
	}
}
