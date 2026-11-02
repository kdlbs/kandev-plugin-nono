package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func openAuditRuntime(root *os.Root) (*os.File, error) {
	return root.OpenFile("runtime/nono-linux-amd64", os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}

func configureAuditVerifierProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = time.Second
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
}
